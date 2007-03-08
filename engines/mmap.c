/*
 * regular read/write sync io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>

#include "../fio.h"
#include "../os.h"

static int fio_mmapio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	unsigned long long real_off = io_u->offset - f->file_offset;

	if (io_u->ddir == DDIR_READ)
		memcpy(io_u->xfer_buf, f->mmap + real_off, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_WRITE)
		memcpy(f->mmap + real_off, io_u->xfer_buf, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_SYNC) {
		if (msync(f->mmap, f->file_size, MS_SYNC))
			io_u->error = errno;
	}

	/*
	 * not really direct, but should drop the pages from the cache
	 */
	if (td->odirect && io_u->ddir != DDIR_SYNC) {
		if (msync(f->mmap + real_off, io_u->xfer_buflen, MS_SYNC) < 0)
			io_u->error = errno;
		if (madvise(f->mmap + real_off, io_u->xfer_buflen,  MADV_DONTNEED) < 0)
			io_u->error = errno;
	}

	if (io_u->error)
		td_verror(td, io_u->error, "sync");

	return FIO_Q_COMPLETED;
}

static int fio_mmapio_init(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	if (!td_write(td))
		return 0;

	/*
	 * We need to truncate the files to the right size, if
	 * we are writing to it.
	 */
	for_each_file(td, f, i) {
		if (ftruncate(f->fd, f->file_size) < 0) {
			td_verror(td, errno, "ftruncate");
			return 1;
		}
	}

	return 0;
}

static int fio_mmapio_open(struct thread_data *td, struct fio_file *f)
{
	int ret, flags;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	if (td_rw(td))
		flags = PROT_READ | PROT_WRITE;
	else if (td_write(td)) {
		flags = PROT_WRITE;

		if (td->verify != VERIFY_NONE)
			flags |= PROT_READ;
	} else
		flags = PROT_READ;

	f->mmap = mmap(NULL, f->file_size, flags, MAP_SHARED, f->fd, f->file_offset);
	if (f->mmap == MAP_FAILED) {
		f->mmap = NULL;
		td_verror(td, errno, "mmap");
		goto err;
	}

	if (file_invalidate_cache(td, f))
		goto err;

	if (!td_random(td)) {
		if (madvise(f->mmap, f->file_size, MADV_SEQUENTIAL) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	} else {
		if (madvise(f->mmap, f->file_size, MADV_RANDOM) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	}

	return 0;

err:
	if (f->mmap)
		munmap(f->mmap, f->file_size);
	generic_close_file(td, f);
	return 1;
}

static void fio_mmapio_close(struct thread_data fio_unused *td,
			     struct fio_file *f)
{
	if (f->mmap) {
		munmap(f->mmap, f->file_size);
		f->mmap = NULL;
	}
}

static struct ioengine_ops ioengine = {
	.name		= "mmap",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_mmapio_queue,
	.init		= fio_mmapio_init,
	.open_file	= fio_mmapio_open,
	.close_file	= fio_mmapio_close,
	.flags		= FIO_SYNCIO,
};

static void fio_init fio_mmapio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_mmapio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
