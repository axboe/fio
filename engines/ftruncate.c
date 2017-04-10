/*
 * ftruncate: ioengine for git://git.kernel.dk/fio.git
 *
 * IO engine that does regular truncates to simulate data transfer
 * as fio ioengine.
 * DDIR_WRITE does ftruncate
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/uio.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>

#include "../fio.h"
#include "../filehash.h"

static int fio_ftruncate_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;
	fio_ro_check(td, io_u);

	if (io_u->ddir != DDIR_WRITE) {
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}
	ret = ftruncate(f->fd, io_u->offset);

	if (ret)
		io_u->error = errno;

	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name		= "ftruncate",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_ftruncate_queue,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO | FIO_FAKEIO
};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
