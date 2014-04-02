/*
 * falloc: ioengine for git://git.kernel.dk/fio.git
 *
 * IO engine that does regular fallocate to simulate data transfer 
 * as fio ioengine.
 * DDIR_READ  does fallocate(,mode = FALLOC_FL_KEEP_SIZE,)
 * DDIR_WRITE does fallocate(,mode = 0) : fallocate with size extension
 * DDIR_TRIM  does fallocate(,mode = FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE)
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

/*
 * generic_open_file is not appropriate because does not allow to perform
 * TRIM in to file
 */
static int open_file(struct thread_data *td, struct fio_file *f)
{
	int from_hash = 0;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (f->filetype != FIO_TYPE_FILE) {
		log_err("fio: only files are supported fallocate \n");
		return 1;
	}
	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

open_again:
	from_hash = file_lookup_open(f, O_CREAT|O_RDWR);

	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int e = errno;

		snprintf(buf, sizeof(buf), "open(%s)", f->file_name);
		td_verror(td, e, buf);
	}

	if (!from_hash && f->fd != -1) {
		if (add_file_hash(f)) {
			int fio_unused ret;

			/*
			 * OK to ignore, we haven't done anything with it
			 */
			ret = generic_close_file(td, f);
			goto open_again;
		}
	}

	return 0;
}

#ifndef FALLOC_FL_KEEP_SIZE
#define FALLOC_FL_KEEP_SIZE     0x01 /* default is extend size */
#endif
#ifndef FALLOC_FL_PUNCH_HOLE
#define FALLOC_FL_PUNCH_HOLE    0x02 /* de-allocates range */
#endif 
static int fio_fallocate_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret;
	int flags = 0;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		flags = FALLOC_FL_KEEP_SIZE;
	else if (io_u->ddir == DDIR_WRITE)
		flags = 0;
	else if (io_u->ddir == DDIR_TRIM)
		flags = FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE;

	ret = fallocate(f->fd, flags, io_u->offset, io_u->xfer_buflen);

	if (ret)
		io_u->error = errno;

	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name		= "falloc",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_fallocate_queue,
	.open_file	= open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO
};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
