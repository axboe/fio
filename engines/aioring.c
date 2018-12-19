/*
 * aioring engine
 *
 * IO engine using the new native Linux libaio ring interface. See:
 *
 * http://git.kernel.dk/cgit/linux-block/log/?h=aio-poll
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libaio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "../fio.h"
#include "../lib/pow2.h"
#include "../optgroup.h"
#include "../lib/memalign.h"

#ifdef ARCH_HAVE_AIORING

#ifndef IOCB_FLAG_HIPRI
#define IOCB_FLAG_HIPRI	(1 << 2)
#endif

/*
 * io_setup2(2) flags
 */
#ifndef IOCTX_FLAG_IOPOLL
#define IOCTX_FLAG_IOPOLL	(1 << 0)
#endif
#ifndef IOCTX_FLAG_SCQRING
#define IOCTX_FLAG_SCQRING	(1 << 1)
#endif
#ifndef IOCTX_FLAG_FIXEDBUFS
#define IOCTX_FLAG_FIXEDBUFS	(1 << 2)
#endif
#ifndef IOCTX_FLAG_SQTHREAD
#define IOCTX_FLAG_SQTHREAD	(1 << 3)
#endif
#ifndef IOCTX_FLAG_SQWQ
#define IOCTX_FLAG_SQWQ		(1 << 4)
#endif
#ifndef IOCTX_FLAG_SQPOLL
#define IOCTX_FLAG_SQPOLL	(1 << 5)
#endif


/*
 * io_ring_enter(2) flags
 */
#ifndef IORING_FLAG_SUBMIT
#define IORING_FLAG_SUBMIT	(1 << 0)
#endif
#ifndef IORING_FLAG_GETEVENTS
#define IORING_FLAG_GETEVENTS	(1 << 1)
#endif

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;

#define IORING_SQ_NEED_WAKEUP	(1 << 0)

#define IOEV_RES2_CACHEHIT	(1 << 0)

struct aio_sq_ring {
	union {
		struct {
			u32 head;
			u32 tail;
			u32 nr_events;
			u16 sq_thread_cpu;
			u16 kflags;
			u64 iocbs;
		};
		u32 pad[16];
	};
	u32 array[0];
};

struct aio_cq_ring {
	union {
		struct {
			u32 head;
			u32 tail;
			u32 nr_events;
		};
		struct io_event pad;
	};
	struct io_event events[0];
};

struct aioring_data {
	io_context_t aio_ctx;
	struct io_u **io_us;
	struct io_u **io_u_index;

	struct aio_sq_ring *sq_ring;
	struct iocb *iocbs;

	struct aio_cq_ring *cq_ring;
	struct io_event *events;

	int queued;
	int cq_ring_off;

	uint64_t cachehit;
	uint64_t cachemiss;
};

struct aioring_options {
	void *pad;
	unsigned int hipri;
	unsigned int fixedbufs;
	unsigned int sqthread;
	unsigned int sqthread_set;
	unsigned int sqthread_poll;
	unsigned int sqwq;
};

static int fio_aioring_sqthread_cb(void *data,
				   unsigned long long *val)
{
	struct aioring_options *o = data;

	o->sqthread = *val;
	o->sqthread_set = 1;
	return 0;
}

static struct fio_option options[] = {
	{
		.name	= "hipri",
		.lname	= "High Priority",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct aioring_options, hipri),
		.help	= "Use polled IO completions",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "fixedbufs",
		.lname	= "Fixed (pre-mapped) IO buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct aioring_options, fixedbufs),
		.help	= "Pre map IO buffers",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqthread",
		.lname	= "Use kernel SQ thread on this CPU",
		.type	= FIO_OPT_INT,
		.cb	= fio_aioring_sqthread_cb,
		.help	= "Offload submission to kernel thread",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqthread_poll",
		.lname	= "Kernel SQ thread should poll",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct aioring_options, sqthread_poll),
		.help	= "Used with sqthread, enables kernel side polling",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqwq",
		.lname	= "Offload submission to kernel workqueue",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct aioring_options, sqwq),
		.help	= "Offload submission to kernel workqueue",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= NULL,
	},
};

static int io_ring_enter(io_context_t ctx, unsigned int to_submit,
			 unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_sys_io_ring_enter, ctx, to_submit, min_complete,
			flags);
}

static int fio_aioring_prep(struct thread_data *td, struct io_u *io_u)
{
	struct aioring_data *ld = td->io_ops_data;
	struct fio_file *f = io_u->file;
	struct aioring_options *o = td->eo;
	struct iocb *iocb;

	iocb = &ld->iocbs[io_u->index];

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (io_u->ddir == DDIR_READ)
			iocb->aio_lio_opcode = IO_CMD_PREAD;
		else
			iocb->aio_lio_opcode = IO_CMD_PWRITE;
		iocb->aio_reqprio = 0;
		iocb->aio_fildes = f->fd;
		iocb->u.c.buf = io_u->xfer_buf;
		iocb->u.c.nbytes = io_u->xfer_buflen;
		iocb->u.c.offset = io_u->offset;
		if (o->hipri)
			iocb->u.c.flags |= IOCB_FLAG_HIPRI;
		else
			iocb->u.c.flags = 0;
	} else if (ddir_sync(io_u->ddir))
		io_prep_fsync(iocb, f->fd);

	iocb->data = io_u;
	return 0;
}

static struct io_u *fio_aioring_event(struct thread_data *td, int event)
{
	struct aioring_data *ld = td->io_ops_data;
	struct io_event *ev;
	struct io_u *io_u;
	int index;

	index = event + ld->cq_ring_off;
	if (index >= ld->cq_ring->nr_events)
		index -= ld->cq_ring->nr_events;

	ev = &ld->cq_ring->events[index];
	io_u = ev->data;

	if (ev->res != io_u->xfer_buflen) {
		if (ev->res > io_u->xfer_buflen)
			io_u->error = -ev->res;
		else
			io_u->resid = io_u->xfer_buflen - ev->res;
	} else
		io_u->error = 0;

	if (io_u->ddir == DDIR_READ) {
		if (ev->res2 & IOEV_RES2_CACHEHIT)
			ld->cachehit++;
		else
			ld->cachemiss++;
	}

	return io_u;
}

static int fio_aioring_cqring_reap(struct thread_data *td, unsigned int events,
				   unsigned int max)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aio_cq_ring *ring = ld->cq_ring;
	u32 head, reaped = 0;

	head = ring->head;
	do {
		read_barrier();
		if (head == ring->tail)
			break;
		reaped++;
		head++;
		if (head == ring->nr_events)
			head = 0;
	} while (reaped + events < max);

	ring->head = head;
	write_barrier();
	return reaped;
}

static int fio_aioring_getevents(struct thread_data *td, unsigned int min,
				 unsigned int max, const struct timespec *t)
{
	struct aioring_data *ld = td->io_ops_data;
	unsigned actual_min = td->o.iodepth_batch_complete_min == 0 ? 0 : min;
	struct aioring_options *o = td->eo;
	struct aio_cq_ring *ring = ld->cq_ring;
	int r, events = 0;

	ld->cq_ring_off = ring->head;
	do {
		r = fio_aioring_cqring_reap(td, events, max);
		if (r) {
			events += r;
			continue;
		}

		if (!o->sqthread_poll) {
			r = io_ring_enter(ld->aio_ctx, 0, actual_min,
						IORING_FLAG_GETEVENTS);
			if (r < 0) {
				if (errno == EAGAIN)
					continue;
				td_verror(td, errno, "io_ring_enter get");
				break;
			}
		}
	} while (events < min);

	return r < 0 ? r : events;
}

static enum fio_q_status fio_aioring_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aio_sq_ring *ring = ld->sq_ring;
	unsigned tail, next_tail;

	fio_ro_check(td, io_u);

	if (ld->queued == td->o.iodepth)
		return FIO_Q_BUSY;

	if (io_u->ddir == DDIR_TRIM) {
		if (ld->queued)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);
		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
		return FIO_Q_COMPLETED;
	}

	tail = ring->tail;
	next_tail = tail + 1;
	if (next_tail == ring->nr_events)
		next_tail = 0;
	read_barrier();
	if (next_tail == ring->head)
		return FIO_Q_BUSY;

	ring->array[tail] = io_u->index;
	ring->tail = next_tail;
	write_barrier();

	ld->queued++;
	return FIO_Q_QUEUED;
}

static void fio_aioring_queued(struct thread_data *td, int start, int nr)
{
	struct aioring_data *ld = td->io_ops_data;
	struct timespec now;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	while (nr--) {
		int index = ld->sq_ring->array[start];
		struct io_u *io_u = io_u = ld->io_u_index[index];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);

		start++;
		if (start == ld->sq_ring->nr_events)
			start = 0;
	}
}

static int fio_aioring_commit(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aioring_options *o = td->eo;
	int ret;

	if (!ld->queued)
		return 0;

	/* Nothing to do */
	if (o->sqthread_poll) {
		struct aio_sq_ring *ring = ld->sq_ring;

		if (ring->kflags & IORING_SQ_NEED_WAKEUP)
			io_ring_enter(ld->aio_ctx, ld->queued, 0, IORING_FLAG_SUBMIT);
		ld->queued = 0;
		return 0;
	}

	do {
		int start = ld->sq_ring->head;
		long nr = ld->queued;

		ret = io_ring_enter(ld->aio_ctx, nr, 0, IORING_FLAG_SUBMIT |
						IORING_FLAG_GETEVENTS);
		if (ret > 0) {
			fio_aioring_queued(td, start, ret);
			io_u_mark_submit(td, ret);

			ld->queued -= ret;
			ret = 0;
		} else if (!ret) {
			io_u_mark_submit(td, ret);
			continue;
		} else {
			if (errno == EAGAIN) {
				ret = fio_aioring_cqring_reap(td, 0, ld->queued);
				if (ret)
					continue;
				/* Shouldn't happen */
				usleep(1);
				continue;
			}
			td_verror(td, errno, "io_ring_enter sumit");
			break;
		}
	} while (ld->queued);

	return ret;
}

static size_t aioring_cq_size(struct thread_data *td)
{
	return sizeof(struct aio_cq_ring) + 2 * td->o.iodepth * sizeof(struct io_event);
}

static size_t aioring_sq_iocb(struct thread_data *td)
{
	return sizeof(struct iocb) * td->o.iodepth;
}

static size_t aioring_sq_size(struct thread_data *td)
{
	return sizeof(struct aio_sq_ring) + td->o.iodepth * sizeof(u32);
}

static void fio_aioring_cleanup(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;

	if (ld) {
		td->ts.cachehit += ld->cachehit;
		td->ts.cachemiss += ld->cachemiss;

		/* Bump depth to match init depth */
		td->o.iodepth++;

		/*
		 * Work-around to avoid huge RCU stalls at exit time. If we
		 * don't do this here, then it'll be torn down by exit_aio().
		 * But for that case we can parallellize the freeing, thus
		 * speeding it up a lot.
		 */
		if (!(td->flags & TD_F_CHILD))
			io_destroy(ld->aio_ctx);
		free(ld->io_u_index);
		free(ld->io_us);
		fio_memfree(ld->sq_ring, aioring_sq_size(td), false);
		fio_memfree(ld->iocbs, aioring_sq_iocb(td), false);
		fio_memfree(ld->cq_ring, aioring_cq_size(td), false);
		free(ld);
	}
}

static int fio_aioring_queue_init(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aioring_options *o = td->eo;
	int flags = IOCTX_FLAG_SCQRING;
	int depth = td->o.iodepth;

	if (o->hipri)
		flags |= IOCTX_FLAG_IOPOLL;
	if (o->sqthread_set) {
		ld->sq_ring->sq_thread_cpu = o->sqthread;
		flags |= IOCTX_FLAG_SQTHREAD;
		if (o->sqthread_poll)
			flags |= IOCTX_FLAG_SQPOLL;
	}
	if (o->sqwq)
		flags |= IOCTX_FLAG_SQWQ;

	if (o->fixedbufs) {
		struct rlimit rlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};

		setrlimit(RLIMIT_MEMLOCK, &rlim);
		flags |= IOCTX_FLAG_FIXEDBUFS;
	}

	return syscall(__NR_sys_io_setup2, depth, flags,
			ld->sq_ring, ld->cq_ring, &ld->aio_ctx);
}

static int fio_aioring_post_init(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aioring_options *o = td->eo;
	struct io_u *io_u;
	struct iocb *iocb;
	int err = 0;

	if (o->fixedbufs) {
		int i;

		for (i = 0; i < td->o.iodepth; i++) {
			io_u = ld->io_u_index[i];
			iocb = &ld->iocbs[i];
			iocb->u.c.buf = io_u->buf;
			iocb->u.c.nbytes = td_max_bs(td);

			if (o->hipri)
				iocb->u.c.flags |= IOCB_FLAG_HIPRI;
		}
	}

	err = fio_aioring_queue_init(td);

	/* Adjust depth back again */
	td->o.iodepth--;

	if (err) {
		td_verror(td, errno, "io_queue_init");
		return 1;
	}

	return 0;
}

static int fio_aioring_init(struct thread_data *td)
{
	struct aioring_data *ld;

	/* ring needs an extra entry, add one to achieve QD set */
	td->o.iodepth++;

	ld = calloc(1, sizeof(*ld));

	/* io_u index */
	ld->io_u_index = calloc(td->o.iodepth, sizeof(struct io_u *));
	ld->io_us = calloc(td->o.iodepth, sizeof(struct io_u *));

	ld->iocbs = fio_memalign(page_size, aioring_sq_iocb(td), false);
	memset(ld->iocbs, 0, aioring_sq_iocb(td));

	ld->sq_ring = fio_memalign(page_size, aioring_sq_size(td), false);
	memset(ld->sq_ring, 0, aioring_sq_size(td));
	ld->sq_ring->nr_events = td->o.iodepth;
	ld->sq_ring->iocbs = (u64) (uintptr_t) ld->iocbs;

	ld->cq_ring = fio_memalign(page_size, aioring_cq_size(td), false);
	memset(ld->cq_ring, 0, aioring_cq_size(td));
	ld->cq_ring->nr_events = td->o.iodepth * 2;

	td->io_ops_data = ld;
	return 0;
}

static int fio_aioring_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct aioring_data *ld = td->io_ops_data;

	ld->io_u_index[io_u->index] = io_u;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "aio-ring",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_aioring_init,
	.post_init		= fio_aioring_post_init,
	.io_u_init		= fio_aioring_io_u_init,
	.prep			= fio_aioring_prep,
	.queue			= fio_aioring_queue,
	.commit			= fio_aioring_commit,
	.getevents		= fio_aioring_getevents,
	.event			= fio_aioring_event,
	.cleanup		= fio_aioring_cleanup,
	.open_file		= generic_open_file,
	.close_file		= generic_close_file,
	.get_file_size		= generic_get_file_size,
	.options		= options,
	.option_struct_size	= sizeof(struct aioring_options),
};

static void fio_init fio_aioring_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_aioring_unregister(void)
{
	unregister_ioengine(&ioengine);
}
#endif
