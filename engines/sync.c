/*
 * regular read/write sync io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

static int fio_syncio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_SYNC)
		return 0;
	if (io_u->offset == f->last_completed_pos)
		return 0;

	if (lseek(f->fd, io_u->offset, SEEK_SET) == -1) {
		td_verror(td, errno, "lseek");
		return 1;
	}

	return 0;
}

static int fio_syncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;

	if (io_u->ddir == DDIR_READ)
		ret = read(f->fd, io_u->xfer_buf, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_WRITE)
		ret = write(f->fd, io_u->xfer_buf, io_u->xfer_buflen);
	else
		ret = fsync(f->fd);

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name		= "sync",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_syncio_prep,
	.queue		= fio_syncio_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.flags		= FIO_SYNCIO,
};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
