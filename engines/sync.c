/*
 * sync/psync engine
 *
 * IO engine that does regular read(2)/write(2) with lseek(2) to transfer
 * data and IO engine that does regular pread(2)/pwrite(2) to transfer data.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../optgroup.h"

/*
 * Sync engine uses engine_data to store last offset
 */
#define LAST_POS(f)	((f)->engine_pos)

struct syncio_data {
	struct iovec *iovecs;
	struct io_u **io_us;
	unsigned int queued;
	unsigned int events;
	unsigned long queued_bytes;

	unsigned long long last_offset;
	struct fio_file *last_file;
	enum fio_ddir last_ddir;
};

#ifdef FIO_HAVE_PWRITEV2
struct psyncv2_options {
	void *pad;
	unsigned int hipri;
};

static struct fio_option options[] = {
	{
		.name	= "hipri",
		.lname	= "RWF_HIPRI",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct psyncv2_options, hipri),
		.help	= "Set RWF_HIPRI for pwritev2/preadv2",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= NULL,
	},
};
#endif

static int fio_syncio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (!ddir_rw(io_u->ddir))
		return 0;

	if (LAST_POS(f) != -1ULL && LAST_POS(f) == io_u->offset)
		return 0;

	if (lseek(f->fd, io_u->offset, SEEK_SET) == -1) {
		td_verror(td, errno, "lseek");
		return 1;
	}

	return 0;
}

static int fio_io_end(struct thread_data *td, struct io_u *io_u, int ret)
{
	if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
		LAST_POS(io_u->file) = io_u->offset + ret;

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error) {
		io_u_log_error(td, io_u);
		td_verror(td, io_u->error, "xfer");
	}

	return FIO_Q_COMPLETED;
}

#ifdef CONFIG_PWRITEV
static int fio_pvsyncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_ops_data;
	struct iovec *iov = &sd->iovecs[0];
	struct fio_file *f = io_u->file;
	int ret;

	fio_ro_check(td, io_u);

	iov->iov_base = io_u->xfer_buf;
	iov->iov_len = io_u->xfer_buflen;

	if (io_u->ddir == DDIR_READ)
		ret = preadv(f->fd, iov, 1, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		ret = pwritev(f->fd, iov, 1, io_u->offset);
	else if (io_u->ddir == DDIR_TRIM) {
		do_io_u_trim(td, io_u);
		return FIO_Q_COMPLETED;
	} else
		ret = do_io_u_sync(td, io_u);

	return fio_io_end(td, io_u, ret);
}
#endif

#ifdef FIO_HAVE_PWRITEV2
static int fio_pvsyncio2_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_ops_data;
	struct psyncv2_options *o = td->eo;
	struct iovec *iov = &sd->iovecs[0];
	struct fio_file *f = io_u->file;
	int ret, flags = 0;

	fio_ro_check(td, io_u);

	if (o->hipri)
		flags |= RWF_HIPRI;

	iov->iov_base = io_u->xfer_buf;
	iov->iov_len = io_u->xfer_buflen;

	if (io_u->ddir == DDIR_READ)
		ret = preadv2(f->fd, iov, 1, io_u->offset, flags);
	else if (io_u->ddir == DDIR_WRITE)
		ret = pwritev2(f->fd, iov, 1, io_u->offset, flags);
	else if (io_u->ddir == DDIR_TRIM) {
		do_io_u_trim(td, io_u);
		return FIO_Q_COMPLETED;
	} else
		ret = do_io_u_sync(td, io_u);

	return fio_io_end(td, io_u, ret);
}
#endif


static int fio_psyncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = pread(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		ret = pwrite(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_TRIM) {
		do_io_u_trim(td, io_u);
		return FIO_Q_COMPLETED;
	} else
		ret = do_io_u_sync(td, io_u);

	return fio_io_end(td, io_u, ret);
}

static int fio_syncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = read(f->fd, io_u->xfer_buf, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_WRITE)
		ret = write(f->fd, io_u->xfer_buf, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_TRIM) {
		do_io_u_trim(td, io_u);
		return FIO_Q_COMPLETED;
	} else
		ret = do_io_u_sync(td, io_u);

	return fio_io_end(td, io_u, ret);
}

static int fio_vsyncio_getevents(struct thread_data *td, unsigned int min,
				 unsigned int max,
				 const struct timespec fio_unused *t)
{
	struct syncio_data *sd = td->io_ops_data;
	int ret;

	if (min) {
		ret = sd->events;
		sd->events = 0;
	} else
		ret = 0;

	dprint(FD_IO, "vsyncio_getevents: min=%d,max=%d: %d\n", min, max, ret);
	return ret;
}

static struct io_u *fio_vsyncio_event(struct thread_data *td, int event)
{
	struct syncio_data *sd = td->io_ops_data;

	return sd->io_us[event];
}

static int fio_vsyncio_append(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_ops_data;

	if (ddir_sync(io_u->ddir))
		return 0;

	if (io_u->offset == sd->last_offset && io_u->file == sd->last_file &&
	    io_u->ddir == sd->last_ddir)
		return 1;

	return 0;
}

static void fio_vsyncio_set_iov(struct syncio_data *sd, struct io_u *io_u,
				int idx)
{
	sd->io_us[idx] = io_u;
	sd->iovecs[idx].iov_base = io_u->xfer_buf;
	sd->iovecs[idx].iov_len = io_u->xfer_buflen;
	sd->last_offset = io_u->offset + io_u->xfer_buflen;
	sd->last_file = io_u->file;
	sd->last_ddir = io_u->ddir;
	sd->queued_bytes += io_u->xfer_buflen;
	sd->queued++;
}

static int fio_vsyncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_ops_data;

	fio_ro_check(td, io_u);

	if (!fio_vsyncio_append(td, io_u)) {
		dprint(FD_IO, "vsyncio_queue: no append (%d)\n", sd->queued);
		/*
		 * If we can't append and have stuff queued, tell fio to
		 * commit those first and then retry this io
		 */
		if (sd->queued)
			return FIO_Q_BUSY;
		if (ddir_sync(io_u->ddir)) {
			int ret = do_io_u_sync(td, io_u);

			return fio_io_end(td, io_u, ret);
		}

		sd->queued = 0;
		sd->queued_bytes = 0;
		fio_vsyncio_set_iov(sd, io_u, 0);
	} else {
		if (sd->queued == td->o.iodepth) {
			dprint(FD_IO, "vsyncio_queue: max depth %d\n", sd->queued);
			return FIO_Q_BUSY;
		}

		dprint(FD_IO, "vsyncio_queue: append\n");
		fio_vsyncio_set_iov(sd, io_u, sd->queued);
	}

	dprint(FD_IO, "vsyncio_queue: depth now %d\n", sd->queued);
	return FIO_Q_QUEUED;
}

/*
 * Check that we transferred all bytes, or saw an error, etc
 */
static int fio_vsyncio_end(struct thread_data *td, ssize_t bytes)
{
	struct syncio_data *sd = td->io_ops_data;
	struct io_u *io_u;
	unsigned int i;
	int err;

	/*
	 * transferred everything, perfect
	 */
	if (bytes == sd->queued_bytes)
		return 0;

	err = errno;
	for (i = 0; i < sd->queued; i++) {
		io_u = sd->io_us[i];

		if (bytes == -1) {
			io_u->error = err;
		} else {
			unsigned int this_io;

			this_io = bytes;
			if (this_io > io_u->xfer_buflen)
				this_io = io_u->xfer_buflen;

			io_u->resid = io_u->xfer_buflen - this_io;
			io_u->error = 0;
			bytes -= this_io;
		}
	}

	if (bytes == -1) {
		td_verror(td, err, "xfer vsync");
		return -err;
	}

	return 0;
}

static int fio_vsyncio_commit(struct thread_data *td)
{
	struct syncio_data *sd = td->io_ops_data;
	struct fio_file *f;
	ssize_t ret;

	if (!sd->queued)
		return 0;

	io_u_mark_submit(td, sd->queued);
	f = sd->last_file;

	if (lseek(f->fd, sd->io_us[0]->offset, SEEK_SET) == -1) {
		int err = -errno;

		td_verror(td, errno, "lseek");
		return err;
	}

	if (sd->last_ddir == DDIR_READ)
		ret = readv(f->fd, sd->iovecs, sd->queued);
	else
		ret = writev(f->fd, sd->iovecs, sd->queued);

	dprint(FD_IO, "vsyncio_commit: %d\n", (int) ret);
	sd->events = sd->queued;
	sd->queued = 0;
	return fio_vsyncio_end(td, ret);
}

static int fio_vsyncio_init(struct thread_data *td)
{
	struct syncio_data *sd;

	sd = malloc(sizeof(*sd));
	memset(sd, 0, sizeof(*sd));
	sd->last_offset = -1ULL;
	sd->iovecs = malloc(td->o.iodepth * sizeof(struct iovec));
	sd->io_us = malloc(td->o.iodepth * sizeof(struct io_u *));

	td->io_ops_data = sd;
	return 0;
}

static void fio_vsyncio_cleanup(struct thread_data *td)
{
	struct syncio_data *sd = td->io_ops_data;

	if (sd) {
		free(sd->iovecs);
		free(sd->io_us);
		free(sd);
	}
}

static struct ioengine_ops ioengine_rw = {
	.name		= "sync",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_syncio_prep,
	.queue		= fio_syncio_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,
};

static struct ioengine_ops ioengine_prw = {
	.name		= "psync",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_psyncio_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,
};

static struct ioengine_ops ioengine_vrw = {
	.name		= "vsync",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_vsyncio_init,
	.cleanup	= fio_vsyncio_cleanup,
	.queue		= fio_vsyncio_queue,
	.commit		= fio_vsyncio_commit,
	.event		= fio_vsyncio_event,
	.getevents	= fio_vsyncio_getevents,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,
};

#ifdef CONFIG_PWRITEV
static struct ioengine_ops ioengine_pvrw = {
	.name		= "pvsync",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_vsyncio_init,
	.cleanup	= fio_vsyncio_cleanup,
	.queue		= fio_pvsyncio_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,
};
#endif

#ifdef FIO_HAVE_PWRITEV2
static struct ioengine_ops ioengine_pvrw2 = {
	.name		= "pvsync2",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_vsyncio_init,
	.cleanup	= fio_vsyncio_cleanup,
	.queue		= fio_pvsyncio2_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO,
	.options	= options,
	.option_struct_size	= sizeof(struct psyncv2_options),
};
#endif

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine_rw);
	register_ioengine(&ioengine_prw);
	register_ioengine(&ioengine_vrw);
#ifdef CONFIG_PWRITEV
	register_ioengine(&ioengine_pvrw);
#endif
#ifdef FIO_HAVE_PWRITEV2
	register_ioengine(&ioengine_pvrw2);
#endif
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine_rw);
	unregister_ioengine(&ioengine_prw);
	unregister_ioengine(&ioengine_vrw);
#ifdef CONFIG_PWRITEV
	unregister_ioengine(&ioengine_pvrw);
#endif
#ifdef FIO_HAVE_PWRITEV2
	unregister_ioengine(&ioengine_pvrw2);
#endif
}
