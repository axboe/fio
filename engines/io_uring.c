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
#include "../lib/roundup.h"

#ifdef ARCH_HAVE_IOURING

#include "../lib/types.h"
#include "../os/linux/io_uring.h"
#include "cmdprio.h"
#include "zbd.h"
#include "nvme.h"

#include <sys/stat.h>

enum uring_cmd_type {
	FIO_URING_CMD_NVME = 1,
};

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
	int prepped;

	struct ioring_mmap mmap[3];

	struct cmdprio cmdprio;
};

struct ioring_options {
	struct thread_data *td;
	unsigned int hipri;
	struct cmdprio_options cmdprio_options;
	unsigned int fixedbufs;
	unsigned int registerfiles;
	unsigned int sqpoll_thread;
	unsigned int sqpoll_set;
	unsigned int sqpoll_cpu;
	unsigned int nonvectored;
	unsigned int uncached;
	unsigned int nowait;
	unsigned int force_async;
	enum uring_cmd_type cmd_type;
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
		.off1	= offsetof(struct ioring_options,
				   cmdprio_options.percentage[DDIR_READ]),
		.off2	= offsetof(struct ioring_options,
				   cmdprio_options.percentage[DDIR_WRITE]),
		.minval	= 0,
		.maxval	= 100,
		.help	= "Send high priority I/O this percentage of the time",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "cmdprio_class",
		.lname	= "Asynchronous I/O priority class",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options,
				   cmdprio_options.class[DDIR_READ]),
		.off2	= offsetof(struct ioring_options,
				   cmdprio_options.class[DDIR_WRITE]),
		.help	= "Set asynchronous IO priority class",
		.minval	= IOPRIO_MIN_PRIO_CLASS + 1,
		.maxval	= IOPRIO_MAX_PRIO_CLASS,
		.interval = 1,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "cmdprio",
		.lname	= "Asynchronous I/O priority level",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options,
				   cmdprio_options.level[DDIR_READ]),
		.off2	= offsetof(struct ioring_options,
				   cmdprio_options.level[DDIR_WRITE]),
		.help	= "Set asynchronous IO priority level",
		.minval	= IOPRIO_MIN_PRIO,
		.maxval	= IOPRIO_MAX_PRIO,
		.interval = 1,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name   = "cmdprio_bssplit",
		.lname  = "Priority percentage block size split",
		.type   = FIO_OPT_STR_STORE,
		.off1   = offsetof(struct ioring_options,
				   cmdprio_options.bssplit_str),
		.help   = "Set priority percentages for different block sizes",
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
	{
		.name	= "cmdprio_class",
		.lname	= "Asynchronous I/O priority class",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support I/O priority classes",
	},
	{
		.name	= "cmdprio",
		.lname	= "Asynchronous I/O priority level",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support I/O priority classes",
	},
	{
		.name   = "cmdprio_bssplit",
		.lname  = "Priority percentage block size split",
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
		.type	= FIO_OPT_STR_SET,
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
		.def	= "-1",
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
		.name	= "nowait",
		.lname	= "RWF_NOWAIT",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct ioring_options, nowait),
		.help	= "Use RWF_NOWAIT for reads/writes",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "force_async",
		.lname	= "Force async",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, force_async),
		.help	= "Set IOSQE_ASYNC every N requests",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "cmd_type",
		.lname	= "Uring cmd type",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct ioring_options, cmd_type),
		.help	= "Specify uring-cmd type",
		.def	= "nvme",
		.posval = {
			  { .ival = "nvme",
			    .oval = FIO_URING_CMD_NVME,
			    .help = "Issue nvme-uring-cmd",
			  },
		},
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
#ifdef FIO_ARCH_HAS_SYSCALL
	return __do_syscall6(__NR_io_uring_enter, ld->ring_fd, to_submit,
				min_complete, flags, NULL, 0);
#else
	return syscall(__NR_io_uring_enter, ld->ring_fd, to_submit,
			min_complete, flags, NULL, 0);
#endif
}

static int fio_ioring_prep(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct fio_file *f = io_u->file;
	struct io_uring_sqe *sqe;

	sqe = &ld->sqes[io_u->index];

	if (o->registerfiles) {
		sqe->fd = f->engine_pos;
		sqe->flags = IOSQE_FIXED_FILE;
	} else {
		sqe->fd = f->fd;
		sqe->flags = 0;
	}

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (o->fixedbufs) {
			sqe->opcode = fixed_ddir_to_op[io_u->ddir];
			sqe->addr = (unsigned long) io_u->xfer_buf;
			sqe->len = io_u->xfer_buflen;
			sqe->buf_index = io_u->index;
		} else {
			struct iovec *iov = &ld->iovecs[io_u->index];

			/*
			 * Update based on actual io_u, requeue could have
			 * adjusted these
			 */
			iov->iov_base = io_u->xfer_buf;
			iov->iov_len = io_u->xfer_buflen;

			sqe->opcode = ddir_to_op[io_u->ddir][!!o->nonvectored];
			if (o->nonvectored) {
				sqe->addr = (unsigned long) iov->iov_base;
				sqe->len = iov->iov_len;
			} else {
				sqe->addr = (unsigned long) iov;
				sqe->len = 1;
			}
		}
		sqe->rw_flags = 0;
		if (!td->o.odirect && o->uncached)
			sqe->rw_flags |= RWF_UNCACHED;
		if (o->nowait)
			sqe->rw_flags |= RWF_NOWAIT;

		/*
		 * Since io_uring can have a submission context (sqthread_poll)
		 * that is different from the process context, we cannot rely on
		 * the IO priority set by ioprio_set() (option prio/prioclass)
		 * to be inherited.
		 * td->ioprio will have the value of the "default prio", so set
		 * this unconditionally. This value might get overridden by
		 * fio_ioring_cmdprio_prep() if the option cmdprio_percentage or
		 * cmdprio_bssplit is used.
		 */
		sqe->ioprio = td->ioprio;
		sqe->off = io_u->offset;
	} else if (ddir_sync(io_u->ddir)) {
		sqe->ioprio = 0;
		if (io_u->ddir == DDIR_SYNC_FILE_RANGE) {
			sqe->off = f->first_write;
			sqe->len = f->last_write - f->first_write;
			sqe->sync_range_flags = td->o.sync_file_range;
			sqe->opcode = IORING_OP_SYNC_FILE_RANGE;
		} else {
			sqe->off = 0;
			sqe->addr = 0;
			sqe->len = 0;
			if (io_u->ddir == DDIR_DATASYNC)
				sqe->fsync_flags |= IORING_FSYNC_DATASYNC;
			sqe->opcode = IORING_OP_FSYNC;
		}
	}

	if (o->force_async && ++ld->prepped == o->force_async) {
		ld->prepped = 0;
		sqe->flags |= IOSQE_ASYNC;
	}

	sqe->user_data = (unsigned long) io_u;
	return 0;
}

static int fio_ioring_cmd_prep(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct fio_file *f = io_u->file;
	struct nvme_uring_cmd *cmd;
	struct io_uring_sqe *sqe;

	/* only supports nvme_uring_cmd */
	if (o->cmd_type != FIO_URING_CMD_NVME)
		return -EINVAL;

	if (io_u->ddir == DDIR_TRIM)
		return 0;

	sqe = &ld->sqes[(io_u->index) << 1];

	if (o->registerfiles) {
		sqe->fd = f->engine_pos;
		sqe->flags = IOSQE_FIXED_FILE;
	} else {
		sqe->fd = f->fd;
	}
	sqe->rw_flags = 0;
	if (!td->o.odirect && o->uncached)
		sqe->rw_flags |= RWF_UNCACHED;
	if (o->nowait)
		sqe->rw_flags |= RWF_NOWAIT;

	sqe->opcode = IORING_OP_URING_CMD;
	sqe->user_data = (unsigned long) io_u;
	if (o->nonvectored)
		sqe->cmd_op = NVME_URING_CMD_IO;
	else
		sqe->cmd_op = NVME_URING_CMD_IO_VEC;
	if (o->force_async && ++ld->prepped == o->force_async) {
		ld->prepped = 0;
		sqe->flags |= IOSQE_ASYNC;
	}
	if (o->fixedbufs) {
		sqe->uring_cmd_flags = IORING_URING_CMD_FIXED;
		sqe->buf_index = io_u->index;
	}

	cmd = (struct nvme_uring_cmd *)sqe->cmd;
	return fio_nvme_uring_cmd_prep(cmd, io_u,
			o->nonvectored ? NULL : &ld->iovecs[io_u->index]);
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

static struct io_u *fio_ioring_cmd_event(struct thread_data *td, int event)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_uring_cqe *cqe;
	struct io_u *io_u;
	unsigned index;

	index = (event + ld->cq_ring_off) & ld->cq_ring_mask;
	if (o->cmd_type == FIO_URING_CMD_NVME)
		index <<= 1;

	cqe = &ld->cq_ring.cqes[index];
	io_u = (struct io_u *) (uintptr_t) cqe->user_data;

	if (cqe->res != 0)
		io_u->error = -cqe->res;
	else
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
		if (head == atomic_load_acquire(ring->tail))
			break;
		reaped++;
		head++;
	} while (reaped + events < max);

	if (reaped)
		atomic_store_release(ring->head, head);

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
			max -= r;
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
				r = -errno;
				td_verror(td, errno, "io_uring_enter");
				break;
			}
		}
	} while (events < min);

	return r < 0 ? r : events;
}

static inline void fio_ioring_cmdprio_prep(struct thread_data *td,
					   struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct cmdprio *cmdprio = &ld->cmdprio;

	if (fio_cmdprio_set_ioprio(td, cmdprio, io_u))
		ld->sqes[io_u->index].ioprio = io_u->ioprio;
}

static int fio_ioring_cmd_io_u_trim(struct thread_data *td,
				    struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;

	if (td->o.zone_mode == ZONE_MODE_ZBD) {
		ret = zbd_do_io_u_trim(td, io_u);
		if (ret == io_u_completed)
			return io_u->xfer_buflen;
		if (ret)
			goto err;
	}

	return fio_nvme_trim(td, f, io_u->offset, io_u->xfer_buflen);

err:
	io_u->error = ret;
	return 0;
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

		if (!strcmp(td->io_ops->name, "io_uring_cmd"))
			fio_ioring_cmd_io_u_trim(td, io_u);
		else
			do_io_u_trim(td, io_u);

		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
		return FIO_Q_COMPLETED;
	}

	tail = *ring->tail;
	next_tail = tail + 1;
	if (next_tail == atomic_load_acquire(ring->head))
		return FIO_Q_BUSY;

	if (ld->cmdprio.mode != CMDPRIO_MODE_NONE)
		fio_ioring_cmdprio_prep(td, io_u);

	ring->array[tail & ld->sq_ring_mask] = io_u->index;
	atomic_store_release(ring->tail, next_tail);

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

	/*
	 * only used for iolog
	 */
	if (td->o.read_iolog_file)
		memcpy(&td->last_issue, &now, sizeof(now));
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
		unsigned start = *ld->sq_ring.head;
		unsigned flags;

		flags = atomic_load_acquire(ring->flags);
		if (flags & IORING_SQ_NEED_WAKEUP)
			io_uring_enter(ld, ld->queued, 0,
					IORING_ENTER_SQ_WAKEUP);
		fio_ioring_queued(td, start, ld->queued);
		io_u_mark_submit(td, ld->queued);

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
			ret = -errno;
			td_verror(td, errno, "io_uring_enter submit");
			break;
		}
	} while (ld->queued);

	return ret;
}

static void fio_ioring_unmap(struct ioring_data *ld)
{
	int i;

	for (i = 0; i < FIO_ARRAY_SIZE(ld->mmap); i++)
		munmap(ld->mmap[i].ptr, ld->mmap[i].len);
	close(ld->ring_fd);
}

static void fio_ioring_cleanup(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;

	if (ld) {
		if (!(td->flags & TD_F_CHILD))
			fio_ioring_unmap(ld);

		fio_cmdprio_cleanup(&ld->cmdprio);
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

	if (p->flags & IORING_SETUP_SQE128)
		ld->mmap[1].len = 2 * p->sq_entries * sizeof(struct io_uring_sqe);
	else
		ld->mmap[1].len = p->sq_entries * sizeof(struct io_uring_sqe);
	ld->sqes = mmap(0, ld->mmap[1].len, PROT_READ | PROT_WRITE,
				MAP_SHARED | MAP_POPULATE, ld->ring_fd,
				IORING_OFF_SQES);
	ld->mmap[1].ptr = ld->sqes;

	if (p->flags & IORING_SETUP_CQE32) {
		ld->mmap[2].len = p->cq_off.cqes +
					2 * p->cq_entries * sizeof(struct io_uring_cqe);
	} else {
		ld->mmap[2].len = p->cq_off.cqes +
					p->cq_entries * sizeof(struct io_uring_cqe);
	}
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

static void fio_ioring_probe(struct thread_data *td)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_uring_probe *p;
	int ret;

	/* already set by user, don't touch */
	if (o->nonvectored != -1)
		return;

	/* default to off, as that's always safe */
	o->nonvectored = 0;

	p = calloc(1, sizeof(*p) + 256 * sizeof(struct io_uring_probe_op));
	if (!p)
		return;

	ret = syscall(__NR_io_uring_register, ld->ring_fd,
			IORING_REGISTER_PROBE, p, 256);
	if (ret < 0)
		goto out;

	if (IORING_OP_WRITE > p->ops_len)
		goto out;

	if ((p->ops[IORING_OP_READ].flags & IO_URING_OP_SUPPORTED) &&
	    (p->ops[IORING_OP_WRITE].flags & IO_URING_OP_SUPPORTED))
		o->nonvectored = 1;
out:
	free(p);
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

		/*
		 * Submission latency for sqpoll_thread is just the time it
		 * takes to fill in the SQ ring entries, and any syscall if
		 * IORING_SQ_NEED_WAKEUP is set, we don't need to log that time
		 * separately.
		 */
		td->o.disable_slat = 1;
	}

	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p.flags |= IORING_SETUP_CQSIZE;
	p.cq_entries = depth;

	/*
	 * Setup COOP_TASKRUN as we don't need to get IPI interrupted for
	 * completing IO operations.
	 */
	p.flags |= IORING_SETUP_COOP_TASKRUN;

	/*
	 * io_uring is always a single issuer, and we can defer task_work
	 * runs until we reap events.
	 */
	p.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

retry:
	ret = syscall(__NR_io_uring_setup, depth, &p);
	if (ret < 0) {
		if (errno == EINVAL && p.flags & IORING_SETUP_DEFER_TASKRUN) {
			p.flags &= ~IORING_SETUP_DEFER_TASKRUN;
			p.flags &= ~IORING_SETUP_SINGLE_ISSUER;
			goto retry;
		}
		if (errno == EINVAL && p.flags & IORING_SETUP_COOP_TASKRUN) {
			p.flags &= ~IORING_SETUP_COOP_TASKRUN;
			goto retry;
		}
		if (errno == EINVAL && p.flags & IORING_SETUP_CQSIZE) {
			p.flags &= ~IORING_SETUP_CQSIZE;
			goto retry;
		}
		return ret;
	}

	ld->ring_fd = ret;

	fio_ioring_probe(td);

	if (o->fixedbufs) {
		ret = syscall(__NR_io_uring_register, ld->ring_fd,
				IORING_REGISTER_BUFFERS, ld->iovecs, depth);
		if (ret < 0)
			return ret;
	}

	return fio_ioring_mmap(ld, &p);
}

static int fio_ioring_cmd_queue_init(struct thread_data *td)
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

		/*
		 * Submission latency for sqpoll_thread is just the time it
		 * takes to fill in the SQ ring entries, and any syscall if
		 * IORING_SQ_NEED_WAKEUP is set, we don't need to log that time
		 * separately.
		 */
		td->o.disable_slat = 1;
	}
	if (o->cmd_type == FIO_URING_CMD_NVME) {
		p.flags |= IORING_SETUP_SQE128;
		p.flags |= IORING_SETUP_CQE32;
	}

	/*
	 * Clamp CQ ring size at our SQ ring size, we don't need more entries
	 * than that.
	 */
	p.flags |= IORING_SETUP_CQSIZE;
	p.cq_entries = depth;

	/*
	 * Setup COOP_TASKRUN as we don't need to get IPI interrupted for
	 * completing IO operations.
	 */
	p.flags |= IORING_SETUP_COOP_TASKRUN;

	/*
	 * io_uring is always a single issuer, and we can defer task_work
	 * runs until we reap events.
	 */
	p.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;

retry:
	ret = syscall(__NR_io_uring_setup, depth, &p);
	if (ret < 0) {
		if (errno == EINVAL && p.flags & IORING_SETUP_DEFER_TASKRUN) {
			p.flags &= ~IORING_SETUP_DEFER_TASKRUN;
			p.flags &= ~IORING_SETUP_SINGLE_ISSUER;
			goto retry;
		}
		if (errno == EINVAL && p.flags & IORING_SETUP_COOP_TASKRUN) {
			p.flags &= ~IORING_SETUP_COOP_TASKRUN;
			goto retry;
		}
		if (errno == EINVAL && p.flags & IORING_SETUP_CQSIZE) {
			p.flags &= ~IORING_SETUP_CQSIZE;
			goto retry;
		}
		return ret;
	}

	ld->ring_fd = ret;

	fio_ioring_probe(td);

	if (o->fixedbufs) {
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
		int init_err = errno;

		if (init_err == ENOSYS)
			log_err("fio: your kernel doesn't support io_uring\n");
		td_verror(td, init_err, "io_queue_init");
		return 1;
	}

	for (i = 0; i < td->o.iodepth; i++) {
		struct io_uring_sqe *sqe;

		sqe = &ld->sqes[i];
		memset(sqe, 0, sizeof(*sqe));
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

static int fio_ioring_cmd_post_init(struct thread_data *td)
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

	err = fio_ioring_cmd_queue_init(td);
	if (err) {
		int init_err = errno;

		td_verror(td, init_err, "io_queue_init");
		return 1;
	}

	for (i = 0; i < td->o.iodepth; i++) {
		struct io_uring_sqe *sqe;

		if (o->cmd_type == FIO_URING_CMD_NVME) {
			sqe = &ld->sqes[i << 1];
			memset(sqe, 0, 2 * sizeof(*sqe));
		} else {
			sqe = &ld->sqes[i];
			memset(sqe, 0, sizeof(*sqe));
		}
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

static int fio_ioring_init(struct thread_data *td)
{
	struct ioring_options *o = td->eo;
	struct ioring_data *ld;
	int ret;

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

	ret = fio_cmdprio_init(td, &ld->cmdprio, &o->cmdprio_options);
	if (ret) {
		td_verror(td, EINVAL, "fio_ioring_init");
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

static int fio_ioring_cmd_open_file(struct thread_data *td, struct fio_file *f)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;

	if (o->cmd_type == FIO_URING_CMD_NVME) {
		struct nvme_data *data = NULL;
		unsigned int nsid, lba_size = 0;
		__u32 ms = 0;
		__u64 nlba = 0;
		int ret;

		/* Store the namespace-id and lba size. */
		data = FILE_ENG_DATA(f);
		if (data == NULL) {
			ret = fio_nvme_get_info(f, &nsid, &lba_size, &ms, &nlba);
			if (ret)
				return ret;

			data = calloc(1, sizeof(struct nvme_data));
			data->nsid = nsid;
			if (ms)
				data->lba_ext = lba_size + ms;
			else
				data->lba_shift = ilog2(lba_size);

			FILE_SET_ENG_DATA(f, data);
		}

		assert(data->lba_shift < 32);
		lba_size = data->lba_ext ? data->lba_ext : (1U << data->lba_shift);

		for_each_rw_ddir(ddir) {
			if (td->o.min_bs[ddir] % lba_size ||
				td->o.max_bs[ddir] % lba_size) {
				if (data->lba_ext)
					log_err("block size must be a multiple of "
						"(LBA data size + Metadata size)\n");
				else
					log_err("block size must be a multiple of LBA data size\n");
				return 1;
			}
                }
	}
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

static int fio_ioring_cmd_close_file(struct thread_data *td,
				     struct fio_file *f)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;

	if (o->cmd_type == FIO_URING_CMD_NVME) {
		struct nvme_data *data = FILE_ENG_DATA(f);

		FILE_SET_ENG_DATA(f, NULL);
		free(data);
	}
	if (!ld || !o->registerfiles)
		return generic_close_file(td, f);

	f->fd = -1;
	return 0;
}

static int fio_ioring_cmd_get_file_size(struct thread_data *td,
					struct fio_file *f)
{
	struct ioring_options *o = td->eo;

	if (fio_file_size_known(f))
		return 0;

	if (o->cmd_type == FIO_URING_CMD_NVME) {
		struct nvme_data *data = NULL;
		unsigned int nsid, lba_size = 0;
		__u32 ms = 0;
		__u64 nlba = 0;
		int ret;

		ret = fio_nvme_get_info(f, &nsid, &lba_size, &ms, &nlba);
		if (ret)
			return ret;

		data = calloc(1, sizeof(struct nvme_data));
		data->nsid = nsid;
		if (ms)
			data->lba_ext = lba_size + ms;
		else
			data->lba_shift = ilog2(lba_size);

		f->real_file_size = lba_size * nlba;
		fio_file_set_size_known(f);

		FILE_SET_ENG_DATA(f, data);
		return 0;
	}
	return generic_get_file_size(td, f);
}

static int fio_ioring_cmd_get_zoned_model(struct thread_data *td,
					  struct fio_file *f,
					  enum zbd_zoned_model *model)
{
	return fio_nvme_get_zoned_model(td, f, model);
}

static int fio_ioring_cmd_report_zones(struct thread_data *td,
				       struct fio_file *f, uint64_t offset,
				       struct zbd_zone *zbdz,
				       unsigned int nr_zones)
{
	return fio_nvme_report_zones(td, f, offset, zbdz, nr_zones);
}

static int fio_ioring_cmd_reset_wp(struct thread_data *td, struct fio_file *f,
				   uint64_t offset, uint64_t length)
{
	return fio_nvme_reset_wp(td, f, offset, length);
}

static int fio_ioring_cmd_get_max_open_zones(struct thread_data *td,
					     struct fio_file *f,
					     unsigned int *max_open_zones)
{
	return fio_nvme_get_max_open_zones(td, f, max_open_zones);
}

static int fio_ioring_cmd_fetch_ruhs(struct thread_data *td, struct fio_file *f,
				     struct fio_ruhs_info *fruhs_info)
{
	struct nvme_fdp_ruh_status *ruhs;
	int bytes, ret, i;

	bytes = sizeof(*ruhs) + 128 * sizeof(struct nvme_fdp_ruh_status_desc);
	ruhs = scalloc(1, bytes);
	if (!ruhs)
		return -ENOMEM;

	ret = fio_nvme_iomgmt_ruhs(td, f, ruhs, bytes);
	if (ret)
		goto free;

	fruhs_info->nr_ruhs = le16_to_cpu(ruhs->nruhsd);
	for (i = 0; i < fruhs_info->nr_ruhs; i++)
		fruhs_info->plis[i] = le16_to_cpu(ruhs->ruhss[i].pid);
free:
	sfree(ruhs);
	return ret;
}

static struct ioengine_ops ioengine_uring = {
	.name			= "io_uring",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_ASYNCIO_SYNC_TRIM | FIO_NO_OFFLOAD |
					FIO_ASYNCIO_SETS_ISSUE_TIME,
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

static struct ioengine_ops ioengine_uring_cmd = {
	.name			= "io_uring_cmd",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_ASYNCIO_SYNC_TRIM | FIO_NO_OFFLOAD |
					FIO_MEMALIGN | FIO_RAWIO |
					FIO_ASYNCIO_SETS_ISSUE_TIME,
	.init			= fio_ioring_init,
	.post_init		= fio_ioring_cmd_post_init,
	.io_u_init		= fio_ioring_io_u_init,
	.prep			= fio_ioring_cmd_prep,
	.queue			= fio_ioring_queue,
	.commit			= fio_ioring_commit,
	.getevents		= fio_ioring_getevents,
	.event			= fio_ioring_cmd_event,
	.cleanup		= fio_ioring_cleanup,
	.open_file		= fio_ioring_cmd_open_file,
	.close_file		= fio_ioring_cmd_close_file,
	.get_file_size		= fio_ioring_cmd_get_file_size,
	.get_zoned_model	= fio_ioring_cmd_get_zoned_model,
	.report_zones		= fio_ioring_cmd_report_zones,
	.reset_wp		= fio_ioring_cmd_reset_wp,
	.get_max_open_zones	= fio_ioring_cmd_get_max_open_zones,
	.options		= options,
	.option_struct_size	= sizeof(struct ioring_options),
	.fdp_fetch_ruhs		= fio_ioring_cmd_fetch_ruhs,
};

static void fio_init fio_ioring_register(void)
{
	register_ioengine(&ioengine_uring);
	register_ioengine(&ioengine_uring_cmd);
}

static void fio_exit fio_ioring_unregister(void)
{
	unregister_ioengine(&ioengine_uring);
	unregister_ioengine(&ioengine_uring_cmd);
}
#endif
