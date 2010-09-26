/*
 * syslet engine
 *
 * IO engine that does regular pread(2)/pwrite(2) to transfer data, but
 * with syslets to make the execution async.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <malloc.h>
#include <asm/unistd.h>

#include "../fio.h"
#include "../lib/fls.h"

#ifdef FIO_HAVE_SYSLET

#ifdef __NR_pread64
#define __NR_fio_pread	__NR_pread64
#define __NR_fio_pwrite	__NR_pwrite64
#else
#define __NR_fio_pread	__NR_pread
#define __NR_fio_pwrite	__NR_pwrite
#endif

struct syslet_data {
	struct io_u **events;
	unsigned int nr_events;
	
	struct syslet_ring *ring;
	unsigned int ring_mask;
	void *stack;
};

static void fio_syslet_add_event(struct thread_data *td, struct io_u *io_u)
{
	struct syslet_data *sd = td->io_ops->data;

	assert(sd->nr_events < td->o.iodepth);
	sd->events[sd->nr_events++] = io_u;
}

static void fio_syslet_add_events(struct thread_data *td, unsigned int nr)
{
	struct syslet_data *sd = td->io_ops->data;
	unsigned int i, uidx;

	uidx = sd->ring->user_tail;
	read_barrier();

	for (i = 0; i < nr; i++) {
		unsigned int idx = (i + uidx) & sd->ring_mask;
		struct syslet_completion *comp = &sd->ring->comp[idx];
		struct io_u *io_u = (struct io_u *) (long) comp->caller_data;
		long ret;

		ret = comp->status;
		if (ret <= 0) {
			io_u->resid = io_u->xfer_buflen;
			io_u->error = -ret;
		} else {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
		}

		fio_syslet_add_event(td, io_u);
	}
}

static void fio_syslet_wait_for_events(struct thread_data *td)
{
	struct syslet_data *sd = td->io_ops->data;
	struct syslet_ring *ring = sd->ring;

	do {
		unsigned int kh = ring->kernel_head;
		int ret;

		/*
		 * first reap events that are already completed
		 */
		if (ring->user_tail != kh) {
			unsigned int nr = kh - ring->user_tail;

			fio_syslet_add_events(td, nr);
			ring->user_tail = kh;
			break;
		}

		/*
		 * block waiting for at least one event
		 */
		ret = syscall(__NR_syslet_ring_wait, ring, ring->user_tail);
		assert(!ret);
	} while (1);
}

static int fio_syslet_getevents(struct thread_data *td, unsigned int min,
				unsigned int fio_unused max,
				struct timespec fio_unused *t)
{
	struct syslet_data *sd = td->io_ops->data;
	long ret;

	/*
	 * While we have less events than requested, block waiting for them
	 * (if we have to, there may already be more completed events ready
	 * for us - see fio_syslet_wait_for_events()
	 */
	while (sd->nr_events < min)
		fio_syslet_wait_for_events(td);

	ret = sd->nr_events;
	sd->nr_events = 0;
	return ret;
}

static struct io_u *fio_syslet_event(struct thread_data *td, int event)
{
	struct syslet_data *sd = td->io_ops->data;

	return sd->events[event];
}

static void fio_syslet_prep_sync(struct fio_file *f,
				 struct indirect_registers *regs)
{
	FILL_IN(*regs, __NR_fsync, (long) f->fd);
}

static void fio_syslet_prep_datasync(struct fio_file *f,
				     struct indirect_registers *regs)
{
	FILL_IN(*regs, __NR_fdatasync, (long) f->fd);
}

static void fio_syslet_prep_rw(struct io_u *io_u, struct fio_file *f,
			       struct indirect_registers *regs)
{
	long nr;

	/*
	 * prepare rw
	 */
	if (io_u->ddir == DDIR_READ)
		nr = __NR_fio_pread;
	else
		nr = __NR_fio_pwrite;

	FILL_IN(*regs, nr, (long) f->fd, (long) io_u->xfer_buf,
		(long) io_u->xfer_buflen, (long) io_u->offset);
}

static void fio_syslet_prep(struct io_u *io_u, struct indirect_registers *regs)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_SYNC)
		fio_syslet_prep_sync(f, regs);
	else if (io_u->ddir == DDIR_DATASYNC)
		fio_syslet_prep_datasync(f, regs);
	else
		fio_syslet_prep_rw(io_u, f, regs);
}

static void ret_func(void)
{
	syscall(__NR_exit);
}

static int fio_syslet_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syslet_data *sd = td->io_ops->data;
	union indirect_params params;
	struct indirect_registers regs;
	int ret;

	fio_ro_check(td, io_u);

	memset(&params, 0, sizeof(params));
	fill_syslet_args(&params.syslet, sd->ring, (long)io_u, ret_func, sd->stack);

	fio_syslet_prep(io_u, &regs);

	ret = syscall(__NR_indirect, &regs, &params, sizeof(params), 0);
	if (ret == (int) io_u->xfer_buflen) {
		/*
		 * completed sync, account. this also catches fsync().
		 */
		return FIO_Q_COMPLETED;
	} else if (ret < 0) {
		/*
		 * queued for async execution
		 */
		if (errno == ESYSLETPENDING)
			return FIO_Q_QUEUED;
	}

	io_u->error = errno;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static int check_syslet_support(struct syslet_data *sd)
{
	union indirect_params params;
	struct indirect_registers regs;
	pid_t pid, my_pid = getpid();

	memset(&params, 0, sizeof(params));
	fill_syslet_args(&params.syslet, sd->ring, 0, ret_func, sd->stack);

	FILL_IN(regs, __NR_getpid);

	pid = syscall(__NR_indirect, &regs, &params, sizeof(params), 0);
	if (pid == my_pid)
		return 0;

	return 1;
}

static void fio_syslet_cleanup(struct thread_data *td)
{
	struct syslet_data *sd = td->io_ops->data;

	if (sd) {
		free(sd->events);
		free(sd->ring);
		free(sd);
	}
}

static int fio_syslet_init(struct thread_data *td)
{
	struct syslet_data *sd;
	void *ring = NULL, *stack = NULL;
	unsigned int ring_size, ring_nr;

	sd = malloc(sizeof(*sd));
	memset(sd, 0, sizeof(*sd));

	sd->events = malloc(sizeof(struct io_u *) * td->o.iodepth);
	memset(sd->events, 0, sizeof(struct io_u *) * td->o.iodepth);

	/*
	 * The ring needs to be a power-of-2, so round it up if we have to
	 */
	ring_nr = td->o.iodepth;
	if (ring_nr & (ring_nr - 1))
		ring_nr = 1 << __fls(ring_nr);

	ring_size = sizeof(struct syslet_ring) +
			ring_nr * sizeof(struct syslet_completion);
	if (posix_memalign(&ring, sizeof(uint64_t), ring_size))
		goto err_mem;
	if (posix_memalign(&stack, page_size, page_size))
		goto err_mem;

	sd->ring = ring;
	sd->ring_mask = ring_nr - 1;
	sd->stack = stack;

	memset(sd->ring, 0, ring_size);
	sd->ring->elements = ring_nr;

	if (!check_syslet_support(sd)) {
		td->io_ops->data = sd;
		return 0;
	}

	log_err("fio: syslets do not appear to work\n");
err_mem:
	free(sd->events);
	if (ring)
		free(ring);
	if (stack)
		free(stack);
	free(sd);
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "syslet-rw",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_syslet_init,
	.queue		= fio_syslet_queue,
	.getevents	= fio_syslet_getevents,
	.event		= fio_syslet_event,
	.cleanup	= fio_syslet_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
};

#else /* FIO_HAVE_SYSLET */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_syslet_init(struct thread_data fio_unused *td)
{
	log_err("fio: syslet not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "syslet-rw",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_syslet_init,
};

#endif /* FIO_HAVE_SYSLET */

static void fio_init fio_syslet_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syslet_unregister(void)
{
	unregister_ioengine(&ioengine);
}
