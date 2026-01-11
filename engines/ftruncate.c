/*
 * ftruncate: ioengine for https://git.kernel.org/pub/scm/linux/kernel/git/axboe/fio
 *
 * IO engine that does regular truncates to simulate data transfer
 * as fio ioengine.
 * DDIR_WRITE does ftruncate
 *
 */
#include <errno.h>
#include <unistd.h>

#include "../fio.h"

static enum fio_q_status fio_ftruncate_queue(struct thread_data *td,
					     struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret = 0;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE)
		ret = ftruncate(f->fd, io_u->offset);
	else if (io_u->ddir == DDIR_SYNC)
		ret = do_io_u_sync(td, io_u);
	else
		io_u->error = EINVAL;

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
