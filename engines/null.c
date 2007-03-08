/*
 * null engine - doesn't do any transfers. Used to test fio.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

static int fio_null_queue(struct thread_data fio_unused *td, struct io_u *io_u)
{
	io_u->resid = 0;
	io_u->error = 0;
	return FIO_Q_COMPLETED;
}

static int fio_null_setup(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	if (!td->total_file_size) {
		log_err("fio: need size= set\n");
		return 1;
	}

	td->io_size = td->total_file_size;
	td->total_io_size = td->io_size;

	for_each_file(td, f, i) {
		f->fd = dup(STDOUT_FILENO);
		f->real_file_size = td->total_io_size / td->nr_files;
		f->file_size = f->real_file_size;
	}

	td->nr_open_files = td->nr_files;
	return 0;
}

static int fio_null_open(struct thread_data fio_unused *td,
			 struct fio_file fio_unused *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "null",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_null_setup,
	.queue		= fio_null_queue,
	.open_file	= fio_null_open,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_null_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_null_unregister(void)
{
	unregister_ioengine(&ioengine);
}
