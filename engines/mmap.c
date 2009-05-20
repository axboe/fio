/*
 * mmap engine
 *
 * IO engine that reads/writes from files by doing memcpy to/from
 * a memory mapped region of the file.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>

#include "../fio.h"

static int fio_mmapio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	unsigned long long real_off = io_u->offset - f->file_offset;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		memcpy(io_u->xfer_buf, f->mmap + real_off, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_WRITE)
		memcpy(f->mmap + real_off, io_u->xfer_buf, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_SYNC) {
		size_t len = (f->io_size + page_size - 1) & ~page_mask;

		if (msync(f->mmap, len, MS_SYNC)) {
			io_u->error = errno;
			td_verror(td, io_u->error, "msync");
		}
	}

	/*
	 * not really direct, but should drop the pages from the cache
	 */
	if (td->o.odirect && io_u->ddir != DDIR_SYNC) {
		size_t len = (io_u->xfer_buflen + page_size - 1) & ~page_mask;
		unsigned long long off = real_off & ~page_mask;

		if (msync(f->mmap + off, len, MS_SYNC) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "msync");
		}
		if (madvise(f->mmap + off, len,  MADV_DONTNEED) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "madvise");
		}
	}

	return FIO_Q_COMPLETED;
}

static int fio_mmapio_open(struct thread_data *td, struct fio_file *f)
{
	int ret, flags;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	/*
	 * for size checkup, don't mmap anything.
	 */
	if (!f->io_size)
		return 0;

	if (td_rw(td))
		flags = PROT_READ | PROT_WRITE;
	else if (td_write(td)) {
		flags = PROT_WRITE;

		if (td->o.verify != VERIFY_NONE)
			flags |= PROT_READ;
	} else
		flags = PROT_READ;

	f->mmap = mmap(NULL, f->io_size, flags, MAP_SHARED, f->fd, f->file_offset);
	if (f->mmap == MAP_FAILED) {
		int err = errno;

		f->mmap = NULL;
		td_verror(td, err, "mmap");
		if (err == EINVAL && f->io_size > 2*1024*1024*1024UL)
			log_err("fio: mmap size likely too large\n");
		goto err;
	}

	if (file_invalidate_cache(td, f))
		goto err;

	if (!td_random(td)) {
		if (madvise(f->mmap, f->io_size, MADV_SEQUENTIAL) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	} else {
		if (madvise(f->mmap, f->io_size, MADV_RANDOM) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	}

	return 0;

err:
	td->io_ops->close_file(td, f);
	return 1;
}

static int fio_mmapio_close(struct thread_data fio_unused *td,
			    struct fio_file *f)
{
	int ret = 0, ret2;

	if (f->mmap) {
		if (munmap(f->mmap, f->io_size) < 0)
			ret = errno;

		f->mmap = NULL;
	}

	ret2 = generic_close_file(td, f);
	if (!ret && ret2)
		ret = ret2;

	return ret;
}

static struct ioengine_ops ioengine = {
	.name		= "mmap",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_mmapio_queue,
	.open_file	= fio_mmapio_open,
	.close_file	= fio_mmapio_close,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO | FIO_NOEXTEND,
};

static void fio_init fio_mmapio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_mmapio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
