/*
 * io_uring engine
 *
 * IO engine using the new native Linux aio io_uring interface. See:
 *
 * http://git.kernel.dk/cgit/linux-block/log/?h=io_uring
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "../fio.h"
#include "../lib/pow2.h"
#include "../optgroup.h"
#include "../lib/memalign.h"
#include "../lib/fls.h"

#ifdef ARCH_HAVE_IOURING

#include "../lib/types.h"
#include "../os/io_uring.h"

struct io_sq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	unsigned *flags;
	unsigned *array;
};

struct io_cq_ring {
	unsigned *head;
	unsigned *tail;
	unsigned *ring_mask;
	unsigned *ring_entries;
	struct io_uring_event *events;
};

struct ioring_mmap {
	void *ptr;
	size_t len;
};

struct ioring_data {
	int ring_fd;

	struct io_u **io_us;
	struct io_u **io_u_index;

	struct io_sq_ring sq_ring;
	struct io_uring_iocb *iocbs;
	struct iovec *iovecs;
	unsigned sq_ring_mask;

	struct io_cq_ring cq_ring;
	unsigned cq_ring_mask;

	int queued;
	int cq_ring_off;
	unsigned iodepth;

	uint64_t cachehit;
	uint64_t cachemiss;

	struct ioring_mmap mmap[3];
};

struct ioring_options {
	void *pad;
	unsigned int hipri;
	unsigned int fixedbufs;
	unsigned int sqthread;
	unsigned int sqthread_set;
	unsigned int sqthread_poll;
	unsigned int sqwq;
};

static int fio_ioring_sqthread_cb(void *data, unsigned long long *val)
{
	struct ioring_options *o = data;

	o->sqthread = *val;
	o->sqthread_set = 1;
	return 0;
}

static struct fio_option options[] = {
	{
		.name	= "hipri",
		.lname	= "High Priority",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, hipri),
		.help	= "Use polled IO completions",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "fixedbufs",
		.lname	= "Fixed (pre-mapped) IO buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, fixedbufs),
		.help	= "Pre map IO buffers",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqthread",
		.lname	= "Use kernel SQ thread on this CPU",
		.type	= FIO_OPT_INT,
		.cb	= fio_ioring_sqthread_cb,
		.help	= "Offload submission to kernel thread",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqthread_poll",
		.lname	= "Kernel SQ thread should poll",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, sqthread_poll),
		.help	= "Used with sqthread, enables kernel side polling",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "sqwq",
		.lname	= "Offload submission to kernel workqueue",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, sqwq),
		.help	= "Offload submission to kernel workqueue",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= NULL,
	},
};

static int io_uring_enter(struct ioring_data *ld, unsigned int to_submit,
			 unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_sys_io_uring_enter, ld->ring_fd, to_submit,
			min_complete, flags);
}

static int fio_ioring_prep(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct fio_file *f = io_u->file;
	struct io_uring_iocb *iocb;

	iocb = &ld->iocbs[io_u->index];
	iocb->fd = f->fd;
	iocb->flags = 0;
	iocb->ioprio = 0;

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (io_u->ddir == DDIR_READ) {
			if (o->fixedbufs)
				iocb->opcode = IORING_OP_READ_FIXED;
			else
				iocb->opcode = IORING_OP_READ;
		} else {
			if (o->fixedbufs)
				iocb->opcode = IORING_OP_WRITE_FIXED;
			else
				iocb->opcode = IORING_OP_WRITE;
		}
		iocb->off = io_u->offset;
		iocb->addr = io_u->xfer_buf;
		iocb->len = io_u->xfer_buflen;
	} else if (ddir_sync(io_u->ddir))
		iocb->opcode = IORING_OP_FSYNC;

	return 0;
}

static struct io_u *fio_ioring_event(struct thread_data *td, int event)
{
	struct ioring_data *ld = td->io_ops_data;
	struct io_uring_event *ev;
	struct io_u *io_u;
	unsigned index;

	index = (event + ld->cq_ring_off) & ld->cq_ring_mask;

	ev = &ld->cq_ring.events[index];
	io_u = ld->io_u_index[ev->index];

	if (ev->res != io_u->xfer_buflen) {
		if (ev->res > io_u->xfer_buflen)
			io_u->error = -ev->res;
		else
			io_u->resid = io_u->xfer_buflen - ev->res;
	} else
		io_u->error = 0;

	if (io_u->ddir == DDIR_READ) {
		if (ev->flags & IOEV_FLAG_CACHEHIT)
			ld->cachehit++;
		else
			ld->cachemiss++;
	}

	return io_u;
}

static int fio_ioring_cqring_reap(struct thread_data *td, unsigned int events,
				   unsigned int max)
{
	struct ioring_data *ld = td->io_ops_data;
	struct io_cq_ring *ring = &ld->cq_ring;
	unsigned head, reaped = 0;

	head = *ring->head;
	do {
		read_barrier();
		if (head == *ring->tail)
			break;
		reaped++;
		head++;
	} while (reaped + events < max);

	*ring->head = head;
	write_barrier();
	return reaped;
}

static int fio_ioring_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct ioring_data *ld = td->io_ops_data;
	unsigned actual_min = td->o.iodepth_batch_complete_min == 0 ? 0 : min;
	struct ioring_options *o = td->eo;
	struct io_cq_ring *ring = &ld->cq_ring;
	unsigned events = 0;
	int r;

	ld->cq_ring_off = *ring->head;
	do {
		r = fio_ioring_cqring_reap(td, events, max);
		if (r) {
			events += r;
			continue;
		}

		if (!o->sqthread_poll) {
			r = io_uring_enter(ld, 0, actual_min,
						IORING_ENTER_GETEVENTS);
			if (r < 0) {
				if (errno == EAGAIN)
					continue;
				td_verror(td, errno, "io_uring_enter");
				break;
			}
		}
	} while (events < min);

	return r < 0 ? r : events;
}

static enum fio_q_status fio_ioring_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct io_sq_ring *ring = &ld->sq_ring;
	unsigned tail, next_tail;

	fio_ro_check(td, io_u);

	if (ld->queued == ld->iodepth)
		return FIO_Q_BUSY;

	if (io_u->ddir == DDIR_TRIM) {
		if (ld->queued)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);
		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
		return FIO_Q_COMPLETED;
	}

	tail = *ring->tail;
	next_tail = tail + 1;
	read_barrier();
	if (next_tail == *ring->head)
		return FIO_Q_BUSY;

	ring->array[tail & ld->sq_ring_mask] = io_u->index;
	*ring->tail = next_tail;
	write_barrier();

	ld->queued++;
	return FIO_Q_QUEUED;
}

static void fio_ioring_queued(struct thread_data *td, int start, int nr)
{
	struct ioring_data *ld = td->io_ops_data;
	struct timespec now;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	while (nr--) {
		struct io_sq_ring *ring = &ld->sq_ring;
		int index = ring->array[start & ld->sq_ring_mask];
		struct io_u *io_u = ld->io_u_index[index];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);

		start++;
	}
}

static int fio_ioring_commit(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	int ret;

	if (!ld->queued)
		return 0;

	/* Nothing to do */
	if (o->sqthread_poll) {
		struct io_sq_ring *ring = &ld->sq_ring;

		if (*ring->flags & IORING_SQ_NEED_WAKEUP)
			io_uring_enter(ld, ld->queued, 0, 0);
		ld->queued = 0;
		return 0;
	}

	do {
		unsigned start = *ld->sq_ring.head;
		long nr = ld->queued;

		ret = io_uring_enter(ld, nr, 0, IORING_ENTER_GETEVENTS);
		if (ret > 0) {
			fio_ioring_queued(td, start, ret);
			io_u_mark_submit(td, ret);

			ld->queued -= ret;
			ret = 0;
		} else if (!ret) {
			io_u_mark_submit(td, ret);
			continue;
		} else {
			if (errno == EAGAIN) {
				ret = fio_ioring_cqring_reap(td, 0, ld->queued);
				if (ret)
					continue;
				/* Shouldn't happen */
				usleep(1);
				continue;
			}
			td_verror(td, errno, "io_uring_enter submit");
			break;
		}
	} while (ld->queued);

	return ret;
}

static void fio_ioring_unmap(struct ioring_data *ld)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ld->mmap); i++)
		munmap(ld->mmap[i].ptr, ld->mmap[i].len);
	close(ld->ring_fd);
}

static void fio_ioring_cleanup(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;

	if (ld) {
		td->ts.cachehit += ld->cachehit;
		td->ts.cachemiss += ld->cachemiss;

		if (!(td->flags & TD_F_CHILD))
			fio_ioring_unmap(ld);

		free(ld->io_u_index);
		free(ld->io_us);
		free(ld->iovecs);
		free(ld);
	}
}

static int fio_ioring_mmap(struct ioring_data *ld, struct io_uring_params *p)
{
	struct io_sq_ring *sring = &ld->sq_ring;
	struct io_cq_ring *cring = &ld->cq_ring;
	void *ptr;

	ld->mmap[0].len = p->sq_off.array + p->sq_entries * sizeof(__u32);
	ptr = mmap(0, ld->mmap[0].len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ld->ring_fd,
			IORING_OFF_SQ_RING);
	ld->mmap[0].ptr = ptr;
	sring->head = ptr + p->sq_off.head;
	sring->tail = ptr + p->sq_off.tail;
	sring->ring_mask = ptr + p->sq_off.ring_mask;
	sring->ring_entries = ptr + p->sq_off.ring_entries;
	sring->flags = ptr + p->sq_off.flags;
	sring->array = ptr + p->sq_off.array;
	ld->sq_ring_mask = *sring->ring_mask;

	ld->mmap[1].len = p->sq_entries * sizeof(struct io_uring_iocb);
	ld->iocbs = mmap(0, ld->mmap[1].len, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, ld->ring_fd,
				IORING_OFF_IOCB);
	ld->mmap[1].ptr = ld->iocbs;

	ld->mmap[2].len = p->cq_off.events +
				p->cq_entries * sizeof(struct io_uring_event);
	ptr = mmap(0, ld->mmap[2].len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ld->ring_fd,
			IORING_OFF_CQ_RING);
	ld->mmap[2].ptr = ptr;
	cring->head = ptr + p->cq_off.head;
	cring->tail = ptr + p->cq_off.tail;
	cring->ring_mask = ptr + p->cq_off.ring_mask;
	cring->ring_entries = ptr + p->cq_off.ring_entries;
	cring->events = ptr + p->cq_off.events;
	ld->cq_ring_mask = *cring->ring_mask;
	return 0;
}

static int fio_ioring_queue_init(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	int depth = td->o.iodepth;
	struct io_uring_params p;
	int ret;

	memset(&p, 0, sizeof(p));

	if (o->hipri)
		p.flags |= IORING_SETUP_IOPOLL;
	if (o->sqthread_set) {
		p.sq_thread_cpu = o->sqthread;
		p.flags |= IORING_SETUP_SQTHREAD;
		if (o->sqthread_poll)
			p.flags |= IORING_SETUP_SQPOLL;
	}
	if (o->sqwq)
		p.flags |= IORING_SETUP_SQWQ;

	if (o->fixedbufs) {
		struct rlimit rlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};

		setrlimit(RLIMIT_MEMLOCK, &rlim);
		p.flags |= IORING_SETUP_FIXEDBUFS;
	}

	ret = syscall(__NR_sys_io_uring_setup, depth, ld->iovecs, &p);
	if (ret < 0)
		return ret;

	ld->ring_fd = ret;
	return fio_ioring_mmap(ld, &p);
}

static int fio_ioring_post_init(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_u *io_u;
	int err;

	if (o->fixedbufs) {
		int i;

		for (i = 0; i < td->o.iodepth; i++) {
			struct iovec *iov = &ld->iovecs[i];

			io_u = ld->io_u_index[i];
			iov->iov_base = io_u->buf;
			iov->iov_len = td_max_bs(td);
		}
	}

	err = fio_ioring_queue_init(td);
	if (err) {
		td_verror(td, errno, "io_queue_init");
		return 1;
	}

	return 0;
}

static unsigned roundup_pow2(unsigned depth)
{
	return 1UL << __fls(depth - 1);
}

static int fio_ioring_init(struct thread_data *td)
{
	struct ioring_data *ld;

	ld = calloc(1, sizeof(*ld));

	/* ring depth must be a power-of-2 */
	ld->iodepth = td->o.iodepth;
	td->o.iodepth = roundup_pow2(td->o.iodepth);

	/* io_u index */
	ld->io_u_index = calloc(td->o.iodepth, sizeof(struct io_u *));
	ld->io_us = calloc(td->o.iodepth, sizeof(struct io_u *));

	ld->iovecs = calloc(td->o.iodepth, sizeof(struct iovec));

	td->io_ops_data = ld;
	return 0;
}

static int fio_ioring_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;

	ld->io_u_index[io_u->index] = io_u;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "io_uring",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_ioring_init,
	.post_init		= fio_ioring_post_init,
	.io_u_init		= fio_ioring_io_u_init,
	.prep			= fio_ioring_prep,
	.queue			= fio_ioring_queue,
	.commit			= fio_ioring_commit,
	.getevents		= fio_ioring_getevents,
	.event			= fio_ioring_event,
	.cleanup		= fio_ioring_cleanup,
	.open_file		= generic_open_file,
	.close_file		= generic_close_file,
	.get_file_size		= generic_get_file_size,
	.options		= options,
	.option_struct_size	= sizeof(struct ioring_options),
};

static void fio_init fio_ioring_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_ioring_unregister(void)
{
	unregister_ioengine(&ioengine);
}
#endif
