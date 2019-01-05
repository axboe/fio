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
#include "../lib/fls.h"

#ifdef ARCH_HAVE_AIORING

/*
 * io_uring_setup(2) flags
 */
#ifndef IOCTX_FLAG_SCQRING
#define IOCTX_FLAG_SCQRING	(1 << 0)
#endif
#ifndef IOCTX_FLAG_IOPOLL
#define IOCTX_FLAG_IOPOLL	(1 << 1)
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

#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_IOCB		0x10000000ULL

/*
 * io_uring_enter(2) flags
 */
#ifndef IORING_ENTER_GETEVENTS
#define IORING_ENTER_GETEVENTS	(1 << 0)
#endif

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;

#define IORING_SQ_NEED_WAKEUP	(1 << 0)

#define IOEV_RES2_CACHEHIT	(1 << 0)

struct aio_sqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 flags;
	u32 array;
};

struct aio_cqring_offsets {
	u32 head;
	u32 tail;
	u32 ring_mask;
	u32 ring_entries;
	u32 overflow;
	u32 events;
};

struct aio_uring_params {
	u32 sq_entries;
	u32 cq_entries;
	u32 flags;
	u16 sq_thread_cpu;
	u16 resv[9];
	struct aio_sqring_offsets sq_off;
	struct aio_cqring_offsets cq_off;
};

struct aio_sq_ring {
	u32 *head;
	u32 *tail;
	u32 *ring_mask;
	u32 *ring_entries;
	u32 *flags;
	u32 *array;
};

struct aio_cq_ring {
	u32 *head;
	u32 *tail;
	u32 *ring_mask;
	u32 *ring_entries;
	struct io_event *events;
};

struct aioring_mmap {
	void *ptr;
	size_t len;
};

struct aioring_data {
	int ring_fd;

	struct io_u **io_us;
	struct io_u **io_u_index;

	struct aio_sq_ring sq_ring;
	struct iocb *iocbs;
	struct iovec *iovecs;
	unsigned sq_ring_mask;

	struct aio_cq_ring cq_ring;
	struct io_event *events;
	unsigned cq_ring_mask;

	int queued;
	int cq_ring_off;
	unsigned iodepth;

	uint64_t cachehit;
	uint64_t cachemiss;

	struct aioring_mmap mmap[3];
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

static int io_uring_enter(struct aioring_data *ld, unsigned int to_submit,
			 unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_sys_io_uring_enter, ld->ring_fd, to_submit,
			min_complete, flags);
}

static int fio_aioring_prep(struct thread_data *td, struct io_u *io_u)
{
	struct aioring_data *ld = td->io_ops_data;
	struct fio_file *f = io_u->file;
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
	unsigned index;

	index = (event + ld->cq_ring_off) & ld->cq_ring_mask;

	ev = &ld->cq_ring.events[index];
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
	struct aio_cq_ring *ring = &ld->cq_ring;
	u32 head, reaped = 0;

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

static int fio_aioring_getevents(struct thread_data *td, unsigned int min,
				 unsigned int max, const struct timespec *t)
{
	struct aioring_data *ld = td->io_ops_data;
	unsigned actual_min = td->o.iodepth_batch_complete_min == 0 ? 0 : min;
	struct aioring_options *o = td->eo;
	struct aio_cq_ring *ring = &ld->cq_ring;
	unsigned events = 0;
	int r;

	ld->cq_ring_off = *ring->head;
	do {
		r = fio_aioring_cqring_reap(td, events, max);
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

static enum fio_q_status fio_aioring_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aio_sq_ring *ring = &ld->sq_ring;
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

static void fio_aioring_queued(struct thread_data *td, int start, int nr)
{
	struct aioring_data *ld = td->io_ops_data;
	struct timespec now;

	if (!fio_fill_issue_time(td))
		return;

	fio_gettime(&now, NULL);

	while (nr--) {
		struct aio_sq_ring *ring = &ld->sq_ring;
		int index = ring->array[start & ld->sq_ring_mask];
		struct io_u *io_u = ld->io_u_index[index];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);

		start++;
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
		struct aio_sq_ring *ring = &ld->sq_ring;

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
			td_verror(td, errno, "io_uring_enter submit");
			break;
		}
	} while (ld->queued);

	return ret;
}

static void fio_aioring_unmap(struct aioring_data *ld)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ld->mmap); i++)
		munmap(ld->mmap[i].ptr, ld->mmap[i].len);
	close(ld->ring_fd);
}

static void fio_aioring_cleanup(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;

	if (ld) {
		td->ts.cachehit += ld->cachehit;
		td->ts.cachemiss += ld->cachemiss;

		/*
		 * Work-around to avoid huge RCU stalls at exit time. If we
		 * don't do this here, then it'll be torn down by exit_aio().
		 * But for that case we can parallellize the freeing, thus
		 * speeding it up a lot.
		 */
		if (!(td->flags & TD_F_CHILD))
			fio_aioring_unmap(ld);

		free(ld->io_u_index);
		free(ld->io_us);
		free(ld->iovecs);
		free(ld);
	}
}

static int fio_aioring_mmap(struct aioring_data *ld, struct aio_uring_params *p)
{
	struct aio_sq_ring *sring = &ld->sq_ring;
	struct aio_cq_ring *cring = &ld->cq_ring;
	void *ptr;

	ld->mmap[0].len = p->sq_off.array + p->sq_entries * sizeof(u32);
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

	ld->mmap[1].len = p->sq_entries * sizeof(struct iocb);
	ld->iocbs = mmap(0, ld->mmap[1].len, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, ld->ring_fd,
				IORING_OFF_IOCB);
	ld->mmap[1].ptr = ld->iocbs;

	ld->mmap[2].len = p->cq_off.events +
				p->cq_entries * sizeof(struct io_event);
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

static int fio_aioring_queue_init(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aioring_options *o = td->eo;
	int depth = td->o.iodepth;
	struct aio_uring_params p;
	int ret;

	memset(&p, 0, sizeof(p));
	p.flags = IOCTX_FLAG_SCQRING;

	if (o->hipri)
		p.flags |= IOCTX_FLAG_IOPOLL;
	if (o->sqthread_set) {
		p.sq_thread_cpu = o->sqthread;
		p.flags |= IOCTX_FLAG_SQTHREAD;
		if (o->sqthread_poll)
			p.flags |= IOCTX_FLAG_SQPOLL;
	}
	if (o->sqwq)
		p.flags |= IOCTX_FLAG_SQWQ;

	if (o->fixedbufs) {
		struct rlimit rlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};

		setrlimit(RLIMIT_MEMLOCK, &rlim);
		p.flags |= IOCTX_FLAG_FIXEDBUFS;
	}

	ret = syscall(__NR_sys_io_uring_setup, depth, ld->iovecs, &p);
	if (ret < 0)
		return ret;

	ld->ring_fd = ret;
	return fio_aioring_mmap(ld, &p);
}

static int fio_aioring_post_init(struct thread_data *td)
{
	struct aioring_data *ld = td->io_ops_data;
	struct aioring_options *o = td->eo;
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

	err = fio_aioring_queue_init(td);
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

static int fio_aioring_init(struct thread_data *td)
{
	struct aioring_data *ld;

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
