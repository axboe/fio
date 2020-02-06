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
#include "../os/linux/io_uring.h"

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
	struct io_uring_cqe *cqes;
};

struct ioring_mmap {
	void *ptr;
	size_t len;
};

struct ioring_data {
	int ring_fd;

	struct io_u **io_u_index;

	int *fds;

	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct iovec *iovecs;
	unsigned sq_ring_mask;

	struct io_cq_ring cq_ring;
	unsigned cq_ring_mask;

	int queued;
	int cq_ring_off;
	unsigned iodepth;

	struct ioring_mmap mmap[3];
};

struct ioring_options {
	void *pad;
	unsigned int hipri;
	unsigned int cmdprio_percentage;
	unsigned int fixedbufs;
	unsigned int registerfiles;
	unsigned int sqpoll_thread;
	unsigned int sqpoll_set;
	unsigned int sqpoll_cpu;
	unsigned int nonvectored;
	unsigned int uncached;
};

static const int ddir_to_op[2][2] = {
	{ IORING_OP_READV, IORING_OP_READ },
	{ IORING_OP_WRITEV, IORING_OP_WRITE }
};

static const int fixed_ddir_to_op[2] = {
	IORING_OP_READ_FIXED,
	IORING_OP_WRITE_FIXED
};

static int fio_ioring_sqpoll_cb(void *data, unsigned long long *val)
{
	struct ioring_options *o = data;

	o->sqpoll_cpu = *val;
	o->sqpoll_set = 1;
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
		.group	= FIO_OPT_G_IOURING,
	},
#ifdef FIO_HAVE_IOPRIO_CLASS
	{
		.name	= "cmdprio_percentage",
		.lname	= "high priority percentage",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, cmdprio_percentage),
		.minval	= 1,
		.maxval	= 100,
		.help	= "Send high priority I/O this percentage of the time",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
#else
	{
		.name	= "cmdprio_percentage",
		.lname	= "high priority percentage",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support I/O priority classes",
	},
#endif
	{
		.name	= "fixedbufs",
		.lname	= "Fixed (pre-mapped) IO buffers",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, fixedbufs),
		.help	= "Pre map IO buffers",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "registerfiles",
		.lname	= "Register file set",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct ioring_options, registerfiles),
		.help	= "Pre-open/register files",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "sqthread_poll",
		.lname	= "Kernel SQ thread polling",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, sqpoll_thread),
		.help	= "Offload submission/completion to kernel thread",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "sqthread_poll_cpu",
		.lname	= "SQ Thread Poll CPU",
		.type	= FIO_OPT_INT,
		.cb	= fio_ioring_sqpoll_cb,
		.help	= "What CPU to run SQ thread polling on",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "nonvectored",
		.lname	= "Non-vectored",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, nonvectored),
		.help	= "Use non-vectored read/write commands",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "uncached",
		.lname	= "Uncached",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, uncached),
		.help	= "Use RWF_UNCACHED for buffered read/writes",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= NULL,
	},
};

static int io_uring_enter(struct ioring_data *ld, unsigned int to_submit,
			 unsigned int min_complete, unsigned int flags)
{
	return syscall(__NR_io_uring_enter, ld->ring_fd, to_submit,
			min_complete, flags, NULL, 0);
}

static int fio_ioring_prep(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct fio_file *f = io_u->file;
	struct io_uring_sqe *sqe;

	sqe = &ld->sqes[io_u->index];

	/* zero out fields not used in this submission */
	memset(sqe, 0, sizeof(*sqe));

	if (o->registerfiles) {
		sqe->fd = f->engine_pos;
		sqe->flags = IOSQE_FIXED_FILE;
	} else {
		sqe->fd = f->fd;
	}

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (o->fixedbufs) {
			sqe->opcode = fixed_ddir_to_op[io_u->ddir];
			sqe->addr = (unsigned long) io_u->xfer_buf;
			sqe->len = io_u->xfer_buflen;
			sqe->buf_index = io_u->index;
		} else {
			sqe->opcode = ddir_to_op[io_u->ddir][!!o->nonvectored];
			if (o->nonvectored) {
				sqe->addr = (unsigned long)
						ld->iovecs[io_u->index].iov_base;
				sqe->len = ld->iovecs[io_u->index].iov_len;
			} else {
				sqe->addr = (unsigned long) &ld->iovecs[io_u->index];
				sqe->len = 1;
			}
		}
		if (!td->o.odirect && o->uncached)
			sqe->rw_flags = RWF_UNCACHED;
		if (fio_option_is_set(&td->o, ioprio_class))
			sqe->ioprio = td->o.ioprio_class << 13;
		if (fio_option_is_set(&td->o, ioprio))
			sqe->ioprio |= td->o.ioprio;
		sqe->off = io_u->offset;
	} else if (ddir_sync(io_u->ddir)) {
		if (io_u->ddir == DDIR_SYNC_FILE_RANGE) {
			sqe->off = f->first_write;
			sqe->len = f->last_write - f->first_write;
			sqe->sync_range_flags = td->o.sync_file_range;
			sqe->opcode = IORING_OP_SYNC_FILE_RANGE;
		} else {
			if (io_u->ddir == DDIR_DATASYNC)
				sqe->fsync_flags |= IORING_FSYNC_DATASYNC;
			sqe->opcode = IORING_OP_FSYNC;
		}
	}

	sqe->user_data = (unsigned long) io_u;
	return 0;
}

static struct io_u *fio_ioring_event(struct thread_data *td, int event)
{
	struct ioring_data *ld = td->io_ops_data;
	struct io_uring_cqe *cqe;
	struct io_u *io_u;
	unsigned index;

	index = (event + ld->cq_ring_off) & ld->cq_ring_mask;

	cqe = &ld->cq_ring.cqes[index];
	io_u = (struct io_u *) (uintptr_t) cqe->user_data;

	if (cqe->res != io_u->xfer_buflen) {
		if (cqe->res > io_u->xfer_buflen)
			io_u->error = -cqe->res;
		else
			io_u->resid = io_u->xfer_buflen - cqe->res;
	} else
		io_u->error = 0;

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
			if (actual_min != 0)
				actual_min -= r;
			continue;
		}

		if (!o->sqpoll_thread) {
			r = io_uring_enter(ld, 0, actual_min,
						IORING_ENTER_GETEVENTS);
			if (r < 0) {
				if (errno == EAGAIN || errno == EINTR)
					continue;
				td_verror(td, errno, "io_uring_enter");
				break;
			}
		}
	} while (events < min);

	return r < 0 ? r : events;
}

static void fio_ioring_prio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_options *o = td->eo;
	struct ioring_data *ld = td->io_ops_data;
	if (rand_between(&td->prio_state, 0, 99) < o->cmdprio_percentage) {
		ld->sqes[io_u->index].ioprio = IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT;
		io_u->flags |= IO_U_F_PRIORITY;
	}
	return;
}

static enum fio_q_status fio_ioring_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct io_sq_ring *ring = &ld->sq_ring;
	struct ioring_options *o = td->eo;
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

	/* ensure sqe stores are ordered with tail update */
	write_barrier();
	if (o->cmdprio_percentage)
		fio_ioring_prio_prep(td, io_u);
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

	/*
	 * Kernel side does submission. just need to check if the ring is
	 * flagged as needing a kick, if so, call io_uring_enter(). This
	 * only happens if we've been idle too long.
	 */
	if (o->sqpoll_thread) {
		struct io_sq_ring *ring = &ld->sq_ring;

		read_barrier();
		if (*ring->flags & IORING_SQ_NEED_WAKEUP)
			io_uring_enter(ld, ld->queued, 0,
					IORING_ENTER_SQ_WAKEUP);
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
			if (errno == EAGAIN || errno == EINTR) {
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
		if (!(td->flags & TD_F_CHILD))
			fio_ioring_unmap(ld);

		free(ld->io_u_index);
		free(ld->iovecs);
		free(ld->fds);
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

	ld->mmap[1].len = p->sq_entries * sizeof(struct io_uring_sqe);
	ld->sqes = mmap(0, ld->mmap[1].len, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, ld->ring_fd,
				IORING_OFF_SQES);
	ld->mmap[1].ptr = ld->sqes;

	ld->mmap[2].len = p->cq_off.cqes +
				p->cq_entries * sizeof(struct io_uring_cqe);
	ptr = mmap(0, ld->mmap[2].len, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_POPULATE, ld->ring_fd,
			IORING_OFF_CQ_RING);
	ld->mmap[2].ptr = ptr;
	cring->head = ptr + p->cq_off.head;
	cring->tail = ptr + p->cq_off.tail;
	cring->ring_mask = ptr + p->cq_off.ring_mask;
	cring->ring_entries = ptr + p->cq_off.ring_entries;
	cring->cqes = ptr + p->cq_off.cqes;
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
	if (o->sqpoll_thread) {
		p.flags |= IORING_SETUP_SQPOLL;
		if (o->sqpoll_set) {
			p.flags |= IORING_SETUP_SQ_AFF;
			p.sq_thread_cpu = o->sqpoll_cpu;
		}
	}

	ret = syscall(__NR_io_uring_setup, depth, &p);
	if (ret < 0)
		return ret;

	ld->ring_fd = ret;

	if (o->fixedbufs) {
		struct rlimit rlim = {
			.rlim_cur = RLIM_INFINITY,
			.rlim_max = RLIM_INFINITY,
		};

		if (setrlimit(RLIMIT_MEMLOCK, &rlim) < 0)
			return -1;

		ret = syscall(__NR_io_uring_register, ld->ring_fd,
				IORING_REGISTER_BUFFERS, ld->iovecs, depth);
		if (ret < 0)
			return ret;
	}

	return fio_ioring_mmap(ld, &p);
}

static int fio_ioring_register_files(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct fio_file *f;
	unsigned int i;
	int ret;

	ld->fds = calloc(td->o.nr_files, sizeof(int));

	for_each_file(td, f, i) {
		ret = generic_open_file(td, f);
		if (ret)
			goto err;
		ld->fds[i] = f->fd;
		f->engine_pos = i;
	}

	ret = syscall(__NR_io_uring_register, ld->ring_fd,
			IORING_REGISTER_FILES, ld->fds, td->o.nr_files);
	if (ret) {
err:
		free(ld->fds);
		ld->fds = NULL;
	}

	/*
	 * Pretend the file is closed again, and really close it if we hit
	 * an error.
	 */
	for_each_file(td, f, i) {
		if (ret) {
			int fio_unused ret2;
			ret2 = generic_close_file(td, f);
		} else
			f->fd = -1;
	}

	return ret;
}

static int fio_ioring_post_init(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_u *io_u;
	int err, i;

	for (i = 0; i < td->o.iodepth; i++) {
		struct iovec *iov = &ld->iovecs[i];

		io_u = ld->io_u_index[i];
		iov->iov_base = io_u->buf;
		iov->iov_len = td_max_bs(td);
	}

	err = fio_ioring_queue_init(td);
	if (err) {
		td_verror(td, errno, "io_queue_init");
		return 1;
	}

	if (o->registerfiles) {
		err = fio_ioring_register_files(td);
		if (err) {
			td_verror(td, errno, "ioring_register_files");
			return 1;
		}
	}

	return 0;
}

static unsigned roundup_pow2(unsigned depth)
{
	return 1UL << __fls(depth - 1);
}

static int fio_ioring_init(struct thread_data *td)
{
	struct ioring_options *o = td->eo;
	struct ioring_data *ld;
	struct thread_options *to = &td->o;

	/* sqthread submission requires registered files */
	if (o->sqpoll_thread)
		o->registerfiles = 1;

	if (o->registerfiles && td->o.nr_files != td->o.open_files) {
		log_err("fio: io_uring registered files require nr_files to "
			"be identical to open_files\n");
		return 1;
	}

	ld = calloc(1, sizeof(*ld));

	/* ring depth must be a power-of-2 */
	ld->iodepth = td->o.iodepth;
	td->o.iodepth = roundup_pow2(td->o.iodepth);

	/* io_u index */
	ld->io_u_index = calloc(td->o.iodepth, sizeof(struct io_u *));
	ld->iovecs = calloc(td->o.iodepth, sizeof(struct iovec));

	td->io_ops_data = ld;

	/*
	 * Check for option conflicts
	 */
	if ((fio_option_is_set(to, ioprio) || fio_option_is_set(to, ioprio_class)) &&
			o->cmdprio_percentage != 0) {
		log_err("%s: cmdprio_percentage option and mutually exclusive "
				"prio or prioclass option is set, exiting\n", to->name);
		td_verror(td, EINVAL, "fio_io_uring_init");
		return 1;
	}
	return 0;
}

static int fio_ioring_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;

	ld->io_u_index[io_u->index] = io_u;
	return 0;
}

static int fio_ioring_open_file(struct thread_data *td, struct fio_file *f)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;

	if (!ld || !o->registerfiles)
		return generic_open_file(td, f);

	f->fd = ld->fds[f->engine_pos];
	return 0;
}

static int fio_ioring_close_file(struct thread_data *td, struct fio_file *f)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;

	if (!ld || !o->registerfiles)
		return generic_close_file(td, f);

	f->fd = -1;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "io_uring",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_ASYNCIO_SYNC_TRIM,
	.init			= fio_ioring_init,
	.post_init		= fio_ioring_post_init,
	.io_u_init		= fio_ioring_io_u_init,
	.prep			= fio_ioring_prep,
	.queue			= fio_ioring_queue,
	.commit			= fio_ioring_commit,
	.getevents		= fio_ioring_getevents,
	.event			= fio_ioring_event,
	.cleanup		= fio_ioring_cleanup,
	.open_file		= fio_ioring_open_file,
	.close_file		= fio_ioring_close_file,
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
