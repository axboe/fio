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
#include "../verify.h"

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

enum uring_cmd_write_mode {
	FIO_URING_CMD_WMODE_WRITE = 1,
	FIO_URING_CMD_WMODE_UNCOR,
	FIO_URING_CMD_WMODE_ZEROES,
	FIO_URING_CMD_WMODE_VERIFY,
};

enum uring_cmd_verify_mode {
	FIO_URING_CMD_VMODE_READ = 1,
	FIO_URING_CMD_VMODE_COMPARE,
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
	char *md_buf;

	int *fds;

	struct io_sq_ring sq_ring;
	struct io_uring_sqe *sqes;
	struct iovec *iovecs;
	unsigned sq_ring_mask;

	struct io_cq_ring cq_ring;
	unsigned cq_ring_mask;

	int async_trim_fail;
	int queued;
	int cq_ring_off;
	unsigned iodepth;
	int prepped;

	struct ioring_mmap mmap[3];

	struct cmdprio cmdprio;

	struct nvme_dsm *dsm;
	uint32_t cdw12_flags[DDIR_RWDIR_CNT];
	uint8_t write_opcode;
};

struct ioring_options {
	struct thread_data *td;
	unsigned int hipri;
	unsigned int readfua;
	unsigned int writefua;
	unsigned int deac;
	unsigned int write_mode;
	unsigned int verify_mode;
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
	unsigned int md_per_io_size;
	unsigned int pi_act;
	unsigned int apptag;
	unsigned int apptag_mask;
	unsigned int prchk;
	char *pi_chk;
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
	{
		.name	= "readfua",
		.lname	= "Read fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct ioring_options, readfua),
		.help	= "Set FUA flag (force unit access) for all Read operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "writefua",
		.lname	= "Write fua flag support",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct ioring_options, writefua),
		.help	= "Set FUA flag (force unit access) for all Write operations",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "write_mode",
		.lname	= "Additional Write commands support (Write Uncorrectable, Write Zeores)",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct ioring_options, write_mode),
		.help	= "Issue Write Uncorrectable or Zeroes command instead of Write command",
		.def	= "write",
		.posval = {
			  { .ival = "write",
			    .oval = FIO_URING_CMD_WMODE_WRITE,
			    .help = "Issue Write commands for write operations"
			  },
			  { .ival = "uncor",
			    .oval = FIO_URING_CMD_WMODE_UNCOR,
			    .help = "Issue Write Uncorrectable commands for write operations"
			  },
			  { .ival = "zeroes",
			    .oval = FIO_URING_CMD_WMODE_ZEROES,
			    .help = "Issue Write Zeroes commands for write operations"
			  },
			  { .ival = "verify",
			    .oval = FIO_URING_CMD_WMODE_VERIFY,
			    .help = "Issue Verify commands for write operations"
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "verify_mode",
		.lname	= "Do verify based on the configured command (e.g., Read or Compare command)",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct ioring_options, verify_mode),
		.help	= "Issue Read or Compare command in the verification phase",
		.def	= "read",
		.posval = {
			  { .ival = "read",
			    .oval = FIO_URING_CMD_VMODE_READ,
			    .help = "Issue Read commands in the verification phase"
			  },
			  { .ival = "compare",
			    .oval = FIO_URING_CMD_VMODE_COMPARE,
			    .help = "Issue Compare commands in the verification phase"
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
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
		.help	= "Use RWF_DONTCACHE for buffered read/writes",
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
	CMDPRIO_OPTIONS(struct ioring_options, FIO_OPT_G_IOURING),
	{
		.name	= "md_per_io_size",
		.lname	= "Separate Metadata Buffer Size per I/O",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, md_per_io_size),
		.def	= "0",
		.help	= "Size of separate metadata buffer per I/O (Default: 0)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "pi_act",
		.lname	= "Protection Information Action",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct ioring_options, pi_act),
		.def	= "1",
		.help	= "Protection Information Action bit (pi_act=1 or pi_act=0)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "pi_chk",
		.lname	= "Protection Information Check",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct ioring_options, pi_chk),
		.def	= NULL,
		.help	= "Control of Protection Information Checking (pi_chk=GUARD,REFTAG,APPTAG)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "apptag",
		.lname	= "Application Tag used in Protection Information",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, apptag),
		.def	= "0x1234",
		.help	= "Application Tag used in Protection Information field (Default: 0x1234)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "apptag_mask",
		.lname	= "Application Tag Mask",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct ioring_options, apptag_mask),
		.def	= "0xffff",
		.help	= "Application Tag Mask used with Application Tag (Default: 0xffff)",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_IOURING,
	},
	{
		.name	= "deac",
		.lname	= "Deallocate bit for write zeroes command",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct ioring_options, deac),
		.help	= "Set DEAC (deallocate) flag for write zeroes command",
		.def	= "0",
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

#ifndef BLOCK_URING_CMD_DISCARD
#define BLOCK_URING_CMD_DISCARD	_IO(0x12, 0)
#endif

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
			sqe->rw_flags |= RWF_DONTCACHE;
		if (o->nowait)
			sqe->rw_flags |= RWF_NOWAIT;
		if (td->o.oatomic && io_u->ddir == DDIR_WRITE)
			sqe->rw_flags |= RWF_ATOMIC;

		/*
		 * Since io_uring can have a submission context (sqthread_poll)
		 * that is different from the process context, we cannot rely on
		 * the IO priority set by ioprio_set() (options prio, prioclass,
		 * and priohint) to be inherited.
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
	} else if (io_u->ddir == DDIR_TRIM) {
		sqe->opcode = IORING_OP_URING_CMD;
		sqe->addr = io_u->offset;
		sqe->addr3 = io_u->xfer_buflen;
		sqe->rw_flags = 0;
		sqe->len = sqe->off = 0;
		sqe->ioprio = 0;
		sqe->cmd_op = BLOCK_URING_CMD_DISCARD;
		sqe->__pad1 = 0;
		sqe->file_index = 0;
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
	struct nvme_dsm *dsm;
	void *ptr = ld->dsm;
	unsigned int dsm_size;
	uint8_t read_opcode = nvme_cmd_read;

	/* only supports nvme_uring_cmd */
	if (o->cmd_type != FIO_URING_CMD_NVME)
		return -EINVAL;

	if (io_u->ddir == DDIR_TRIM && td->io_ops->flags & FIO_ASYNCIO_SYNC_TRIM)
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
		sqe->rw_flags |= RWF_DONTCACHE;
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
	dsm_size = sizeof(*ld->dsm) + td->o.num_range * sizeof(struct nvme_dsm_range);
	ptr += io_u->index * dsm_size;
	dsm = (struct nvme_dsm *)ptr;

	/*
	 * If READ command belongs to the verification phase and the
	 * verify_mode=compare, convert READ to COMPARE command.
	 */
	if (io_u->flags & IO_U_F_VER_LIST && io_u->ddir == DDIR_READ &&
			o->verify_mode == FIO_URING_CMD_VMODE_COMPARE) {
		populate_verify_io_u(td, io_u);
		read_opcode = nvme_cmd_compare;
		io_u_set(td, io_u, IO_U_F_VER_IN_DEV);
	}

	return fio_nvme_uring_cmd_prep(cmd, io_u,
			o->nonvectored ? NULL : &ld->iovecs[io_u->index],
			dsm, read_opcode, ld->write_opcode,
			ld->cdw12_flags[io_u->ddir]);
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

	/* trim returns 0 on success */
	if (cqe->res == io_u->xfer_buflen ||
	    (io_u->ddir == DDIR_TRIM && !cqe->res)) {
		io_u->error = 0;
		return io_u;
	}

	if (cqe->res != io_u->xfer_buflen) {
		if (io_u->ddir == DDIR_TRIM) {
			ld->async_trim_fail = 1;
			cqe->res = 0;
		}
		if (cqe->res > io_u->xfer_buflen)
			io_u->error = -cqe->res;
		else
			io_u->resid = io_u->xfer_buflen - cqe->res;
	}

	return io_u;
}

static struct io_u *fio_ioring_cmd_event(struct thread_data *td, int event)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_uring_cqe *cqe;
	struct io_u *io_u;
	struct nvme_data *data;
	unsigned index;
	int ret;

	index = (event + ld->cq_ring_off) & ld->cq_ring_mask;
	if (o->cmd_type == FIO_URING_CMD_NVME)
		index <<= 1;

	cqe = &ld->cq_ring.cqes[index];
	io_u = (struct io_u *) (uintptr_t) cqe->user_data;

	io_u->error = cqe->res;
	if (io_u->error != 0)
		goto ret;

	if (o->cmd_type == FIO_URING_CMD_NVME) {
		data = FILE_ENG_DATA(io_u->file);
		if (data->pi_type && (io_u->ddir == DDIR_READ) && !o->pi_act) {
			ret = fio_nvme_pi_verify(data, io_u);
			if (ret)
				io_u->error = ret;
		}
	}

ret:
	/*
	 * If IO_U_F_DEVICE_ERROR is not set, io_u->error will be parsed as an
	 * errno, otherwise device-specific error value (status value in CQE).
	 */
	if ((int)io_u->error > 0)
		io_u_set(td, io_u, IO_U_F_DEVICE_ERROR);
	else
		io_u_clear(td, io_u, IO_U_F_DEVICE_ERROR);
	io_u->error = abs((int)io_u->error);
	return io_u;
}

static char *fio_ioring_cmd_errdetails(struct thread_data *td,
				       struct io_u *io_u)
{
	struct ioring_options *o = td->eo;
	unsigned int sct = (io_u->error >> 8) & 0x7;
	unsigned int sc = io_u->error & 0xff;
#define MAXERRDETAIL 1024
#define MAXMSGCHUNK 128
	char *msg, msgchunk[MAXMSGCHUNK];

	if (!(io_u->flags & IO_U_F_DEVICE_ERROR))
		return NULL;

	msg = calloc(1, MAXERRDETAIL);
	strcpy(msg, "io_uring_cmd: ");

	snprintf(msgchunk, MAXMSGCHUNK, "%s: ", io_u->file->file_name);
	strlcat(msg, msgchunk, MAXERRDETAIL);

	if (o->cmd_type == FIO_URING_CMD_NVME) {
		strlcat(msg, "cq entry status (", MAXERRDETAIL);

		snprintf(msgchunk, MAXMSGCHUNK, "sct=0x%02x; ", sct);
		strlcat(msg, msgchunk, MAXERRDETAIL);

		snprintf(msgchunk, MAXMSGCHUNK, "sc=0x%02x)", sc);
		strlcat(msg, msgchunk, MAXERRDETAIL);
	} else {
		/* Print status code in generic */
		snprintf(msgchunk, MAXMSGCHUNK, "status=0x%x", io_u->error);
		strlcat(msg, msgchunk, MAXERRDETAIL);
	}

	return msg;
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

static inline void fio_ioring_cmd_nvme_pi(struct thread_data *td,
					  struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct nvme_uring_cmd *cmd;
	struct io_uring_sqe *sqe;
	struct nvme_cmd_ext_io_opts ext_opts = {0};
	struct nvme_data *data = FILE_ENG_DATA(io_u->file);

	if (io_u->ddir == DDIR_TRIM)
		return;

	sqe = &ld->sqes[(io_u->index) << 1];
	cmd = (struct nvme_uring_cmd *)sqe->cmd;

	if (data->pi_type) {
		if (o->pi_act)
			ext_opts.io_flags |= NVME_IO_PRINFO_PRACT;
		ext_opts.io_flags |= o->prchk;
		ext_opts.apptag = o->apptag;
		ext_opts.apptag_mask = o->apptag_mask;
	}

	fio_nvme_pi_fill(cmd, io_u, &ext_opts);
}

static inline void fio_ioring_cmdprio_prep(struct thread_data *td,
					   struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct cmdprio *cmdprio = &ld->cmdprio;

	if (fio_cmdprio_set_ioprio(td, cmdprio, io_u))
		ld->sqes[io_u->index].ioprio = io_u->ioprio;
}

static enum fio_q_status fio_ioring_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct io_sq_ring *ring = &ld->sq_ring;
	unsigned tail, next_tail;

	fio_ro_check(td, io_u);

	/* should not hit... */
	if (ld->queued == td->o.iodepth)
		return FIO_Q_BUSY;

	/* if async trim has been tried and failed, punt to sync */
	if (io_u->ddir == DDIR_TRIM && ld->async_trim_fail) {
		if (ld->queued)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);

		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
		return FIO_Q_COMPLETED;
	}

	tail = *ring->tail;
	next_tail = tail + 1;
	if (next_tail == atomic_load_relaxed(ring->head))
		return FIO_Q_BUSY;

	if (ld->cmdprio.mode != CMDPRIO_MODE_NONE)
		fio_ioring_cmdprio_prep(td, io_u);

	if (!strcmp(td->io_ops->name, "io_uring_cmd") &&
		o->cmd_type == FIO_URING_CMD_NVME)
		fio_ioring_cmd_nvme_pi(td, io_u);

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
		unsigned start = *ld->sq_ring.tail - ld->queued;
		unsigned flags;

		flags = atomic_load_relaxed(ring->flags);
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
		free(ld->md_buf);
		free(ld->iovecs);
		free(ld->fds);
		free(ld->dsm);
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
	int depth = ld->iodepth;
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
	int depth = ld->iodepth;
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

	for (i = 0; i < ld->iodepth; i++) {
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

	for (i = 0; i < ld->iodepth; i++) {
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

static void parse_prchk_flags(struct ioring_options *o)
{
	if (!o->pi_chk)
		return;

	if (strstr(o->pi_chk, "GUARD") != NULL)
		o->prchk = NVME_IO_PRINFO_PRCHK_GUARD;
	if (strstr(o->pi_chk, "REFTAG") != NULL)
		o->prchk |= NVME_IO_PRINFO_PRCHK_REF;
	if (strstr(o->pi_chk, "APPTAG") != NULL)
		o->prchk |= NVME_IO_PRINFO_PRCHK_APP;
}

static int fio_ioring_init(struct thread_data *td)
{
	struct ioring_options *o = td->eo;
	struct ioring_data *ld;
	struct nvme_dsm *dsm;
	void *ptr;
	unsigned int dsm_size;
	unsigned long long md_size;
	int ret, i;

	/* sqthread submission requires registered files */
	if (o->sqpoll_thread)
		o->registerfiles = 1;

	if (o->registerfiles && td->o.nr_files != td->o.open_files) {
		log_err("fio: io_uring registered files require nr_files to "
			"be identical to open_files\n");
		return 1;
	}

	ld = calloc(1, sizeof(*ld));

	/*
	 * The internal io_uring queue depth must be a power-of-2, as that's
	 * how the ring interface works. So round that up, in case the user
	 * set iodepth isn't a power-of-2. Leave the fio depth the same, as
	 * not to be driving too much of an iodepth, if we did round up.
	 */
	ld->iodepth = roundup_pow2(td->o.iodepth);

	/* io_u index */
	ld->io_u_index = calloc(td->o.iodepth, sizeof(struct io_u *));

	/*
	 * metadata buffer for nvme command.
	 * We are only supporting iomem=malloc / mem=malloc as of now.
	 */
	if (!strcmp(td->io_ops->name, "io_uring_cmd") &&
	    (o->cmd_type == FIO_URING_CMD_NVME) && o->md_per_io_size) {
		md_size = (unsigned long long) o->md_per_io_size
				* (unsigned long long) td->o.iodepth;
		md_size += page_mask + td->o.mem_align;
		if (td->o.mem_align && td->o.mem_align > page_size)
			md_size += td->o.mem_align - page_size;
		ld->md_buf = malloc(md_size);
		if (!ld->md_buf) {
			free(ld);
			return 1;
		}
	}
	parse_prchk_flags(o);

	ld->iovecs = calloc(ld->iodepth, sizeof(struct iovec));

	td->io_ops_data = ld;

	ret = fio_cmdprio_init(td, &ld->cmdprio, &o->cmdprio_options);
	if (ret) {
		td_verror(td, EINVAL, "fio_ioring_init");
		return 1;
	}

	/*
	 * For io_uring_cmd, trims are async operations unless we are operating
	 * in zbd mode where trim means zone reset.
	 */
	if (!strcmp(td->io_ops->name, "io_uring_cmd") && td_trim(td) &&
	    td->o.zone_mode == ZONE_MODE_ZBD) {
		td->io_ops->flags |= FIO_ASYNCIO_SYNC_TRIM;
	} else {
		dsm_size = sizeof(*ld->dsm) +
			td->o.num_range * sizeof(struct nvme_dsm_range);
		ld->dsm = calloc(td->o.iodepth, dsm_size);
		ptr = ld->dsm;
		for (i = 0; i < td->o.iodepth; i++) {
			dsm = (struct nvme_dsm *)ptr;
			dsm->nr_ranges = td->o.num_range;
			ptr += dsm_size;
		}
	}

	if (!strcmp(td->io_ops->name, "io_uring_cmd")) {
		if (td_write(td)) {
			switch (o->write_mode) {
			case FIO_URING_CMD_WMODE_UNCOR:
				ld->write_opcode = nvme_cmd_write_uncor;
				break;
			case FIO_URING_CMD_WMODE_ZEROES:
				ld->write_opcode = nvme_cmd_write_zeroes;
				if (o->deac)
					ld->cdw12_flags[DDIR_WRITE] = 1 << 25;
				break;
			case FIO_URING_CMD_WMODE_VERIFY:
				ld->write_opcode = nvme_cmd_verify;
				break;
			default:
				ld->write_opcode = nvme_cmd_write;
				break;
			}
		}

		if (o->readfua)
			ld->cdw12_flags[DDIR_READ] = 1 << 30;
		if (o->writefua)
			ld->cdw12_flags[DDIR_WRITE] = 1 << 30;
	}

	return 0;
}

static int fio_ioring_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_data *ld = td->io_ops_data;
	struct ioring_options *o = td->eo;
	struct nvme_pi_data *pi_data;
	char *p;

	ld->io_u_index[io_u->index] = io_u;

	if (!strcmp(td->io_ops->name, "io_uring_cmd")) {
		p = PTR_ALIGN(ld->md_buf, page_mask) + td->o.mem_align;
		p += o->md_per_io_size * io_u->index;
		io_u->mmap_data = p;

		if (!o->pi_act) {
			pi_data = calloc(1, sizeof(*pi_data));
			pi_data->io_flags |= o->prchk;
			pi_data->apptag_mask = o->apptag_mask;
			pi_data->apptag = o->apptag;
			io_u->engine_data = pi_data;
		}
	}

	return 0;
}

static void fio_ioring_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct ioring_options *o = td->eo;
	struct nvme_pi *pi;

	if (!strcmp(td->io_ops->name, "io_uring_cmd") &&
	    (o->cmd_type == FIO_URING_CMD_NVME)) {
		pi = io_u->engine_data;
		free(pi);
		io_u->engine_data = NULL;
	}
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
		unsigned int lba_size = 0;
		__u64 nlba = 0;
		int ret;

		/* Store the namespace-id and lba size. */
		data = FILE_ENG_DATA(f);
		if (data == NULL) {
			data = calloc(1, sizeof(struct nvme_data));
			ret = fio_nvme_get_info(f, &nlba, o->pi_act, data);
			if (ret) {
				free(data);
				return ret;
			}

			FILE_SET_ENG_DATA(f, data);
		}

		lba_size = data->lba_ext ? data->lba_ext : data->lba_size;

		for_each_rw_ddir(ddir) {
			if (td->o.min_bs[ddir] % lba_size || td->o.max_bs[ddir] % lba_size) {
				if (data->lba_ext) {
					log_err("%s: block size must be a multiple of %u "
						"(LBA data size + Metadata size)\n", f->file_name, lba_size);
					if (td->o.min_bs[ddir] == td->o.max_bs[ddir] &&
					    !(td->o.min_bs[ddir] % data->lba_size)) {
						/* fixed block size is actually a multiple of LBA data size */
						unsigned long long suggestion = lba_size *
							(td->o.min_bs[ddir] / data->lba_size);
						log_err("Did you mean to use a block size of %llu?\n", suggestion);
					}
				} else {
					log_err("%s: block size must be a multiple of LBA data size\n",
						f->file_name);
				}
				td_verror(td, EINVAL, "fio_ioring_cmd_open_file");
				return 1;
			}
			if (data->ms && !data->lba_ext && ddir != DDIR_TRIM &&
			    (o->md_per_io_size < ((td->o.max_bs[ddir] / data->lba_size) *
						  data->ms))) {
				log_err("%s: md_per_io_size should be at least %llu bytes\n",
					f->file_name,
					((td->o.max_bs[ddir] / data->lba_size) * data->ms));
				td_verror(td, EINVAL, "fio_ioring_cmd_open_file");
				return 1;
			}
                }

		/*
		 * For extended logical block sizes we cannot use verify when
		 * end to end data protection checks are enabled, as the PI
		 * section of data buffer conflicts with verify.
		 */
		if (data->ms && data->pi_type && data->lba_ext &&
		    td->o.verify != VERIFY_NONE) {
			log_err("%s: for extended LBA, verify cannot be used when E2E data protection is enabled\n",
				f->file_name);
			td_verror(td, EINVAL, "fio_ioring_cmd_open_file");
			return 1;
		}

		if (o->write_mode != FIO_URING_CMD_WMODE_WRITE &&
		    !td_write(td)) {
			log_err("%s: 'readwrite=|rw=' has no write\n",
					f->file_name);
			td_verror(td, EINVAL, "fio_ioring_cmd_open_file");
			return 1;
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
		__u64 nlba = 0;
		int ret;

		data = calloc(1, sizeof(struct nvme_data));
		ret = fio_nvme_get_info(f, &nlba, o->pi_act, data);
		if (ret) {
			free(data);
			return ret;
		}

		f->real_file_size = data->lba_size * nlba;
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
	int bytes, nr_ruhs, ret, i;

	nr_ruhs = fruhs_info->nr_ruhs;
	bytes = sizeof(*ruhs) + fruhs_info->nr_ruhs * sizeof(struct nvme_fdp_ruh_status_desc);

	ruhs = calloc(1, bytes);
	if (!ruhs)
		return -ENOMEM;

	ret = fio_nvme_iomgmt_ruhs(td, f, ruhs, bytes);
	if (ret)
		goto free;

	fruhs_info->nr_ruhs = le16_to_cpu(ruhs->nruhsd);
	for (i = 0; i < nr_ruhs; i++)
		fruhs_info->plis[i] = le16_to_cpu(ruhs->ruhss[i].pid);
free:
	free(ruhs);
	return ret;
}

static struct ioengine_ops ioengine_uring = {
	.name			= "io_uring",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_NO_OFFLOAD | FIO_ASYNCIO_SETS_ISSUE_TIME |
				  FIO_ATOMICWRITES,
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
	.flags			= FIO_NO_OFFLOAD | FIO_MEMALIGN | FIO_RAWIO |
					FIO_ASYNCIO_SETS_ISSUE_TIME |
					FIO_MULTI_RANGE_TRIM,
	.init			= fio_ioring_init,
	.post_init		= fio_ioring_cmd_post_init,
	.io_u_init		= fio_ioring_io_u_init,
	.io_u_free		= fio_ioring_io_u_free,
	.prep			= fio_ioring_cmd_prep,
	.queue			= fio_ioring_queue,
	.commit			= fio_ioring_commit,
	.getevents		= fio_ioring_getevents,
	.event			= fio_ioring_cmd_event,
	.errdetails		= fio_ioring_cmd_errdetails,
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
