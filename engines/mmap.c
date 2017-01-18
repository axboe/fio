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
#include "../verify.h"

/*
 * Limits us to 1GiB of mapped files in total
 */
#define MMAP_TOTAL_SZ	(1 * 1024 * 1024 * 1024UL)

static unsigned long mmap_map_size;

struct fio_mmap_data {
	void *mmap_ptr;
	size_t mmap_sz;
	off_t mmap_off;
};

static int fio_mmap_file(struct thread_data *td, struct fio_file *f,
			 size_t length, off_t off)
{
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);
	int flags = 0;

	if (td_rw(td))
		flags = PROT_READ | PROT_WRITE;
	else if (td_write(td)) {
		flags = PROT_WRITE;

		if (td->o.verify != VERIFY_NONE)
			flags |= PROT_READ;
	} else
		flags = PROT_READ;

	fmd->mmap_ptr = mmap(NULL, length, flags, MAP_SHARED, f->fd, off);
	if (fmd->mmap_ptr == MAP_FAILED) {
		fmd->mmap_ptr = NULL;
		td_verror(td, errno, "mmap");
		goto err;
	}

	if (!td_random(td)) {
		if (posix_madvise(fmd->mmap_ptr, length, POSIX_MADV_SEQUENTIAL) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	} else {
		if (posix_madvise(fmd->mmap_ptr, length, POSIX_MADV_RANDOM) < 0) {
			td_verror(td, errno, "madvise");
			goto err;
		}
	}
	if (posix_madvise(fmd->mmap_ptr, length, POSIX_MADV_DONTNEED) < 0) {
		td_verror(td, errno, "madvise");
		goto err;
	}

#ifdef FIO_MADV_FREE
	if (f->filetype == FIO_TYPE_BLOCK)
		(void) posix_madvise(fmd->mmap_ptr, fmd->mmap_sz, FIO_MADV_FREE);
#endif

err:
	if (td->error && fmd->mmap_ptr)
		munmap(fmd->mmap_ptr, length);

	return td->error;
}

/*
 * Just mmap an appropriate portion, we cannot mmap the full extent
 */
static int fio_mmapio_prep_limited(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);

	if (io_u->buflen > mmap_map_size) {
		log_err("fio: bs too big for mmap engine\n");
		return EIO;
	}

	fmd->mmap_sz = mmap_map_size;
	if (fmd->mmap_sz  > f->io_size)
		fmd->mmap_sz = f->io_size;

	fmd->mmap_off = io_u->offset;

	return fio_mmap_file(td, f, fmd->mmap_sz, fmd->mmap_off);
}

/*
 * Attempt to mmap the entire file
 */
static int fio_mmapio_prep_full(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);
	int ret;

	if (fio_file_partial_mmap(f))
		return EINVAL;
	if (io_u->offset != (size_t) io_u->offset ||
	    f->io_size != (size_t) f->io_size) {
		fio_file_set_partial_mmap(f);
		return EINVAL;
	}

	fmd->mmap_sz = f->io_size;
	fmd->mmap_off = 0;

	ret = fio_mmap_file(td, f, fmd->mmap_sz, fmd->mmap_off);
	if (ret)
		fio_file_set_partial_mmap(f);

	return ret;
}

static int fio_mmapio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);
	int ret;

	/*
	 * It fits within existing mapping, use it
	 */
	if (io_u->offset >= fmd->mmap_off &&
	    io_u->offset + io_u->buflen < fmd->mmap_off + fmd->mmap_sz)
		goto done;

	/*
	 * unmap any existing mapping
	 */
	if (fmd->mmap_ptr) {
		if (munmap(fmd->mmap_ptr, fmd->mmap_sz) < 0)
			return errno;
		fmd->mmap_ptr = NULL;
	}

	if (fio_mmapio_prep_full(td, io_u)) {
		td_clear_error(td);
		ret = fio_mmapio_prep_limited(td, io_u);
		if (ret)
			return ret;
	}

done:
	io_u->mmap_data = fmd->mmap_ptr + io_u->offset - fmd->mmap_off -
				f->file_offset;
	return 0;
}

static int fio_mmapio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		memcpy(io_u->xfer_buf, io_u->mmap_data, io_u->xfer_buflen);
	else if (io_u->ddir == DDIR_WRITE)
		memcpy(io_u->mmap_data, io_u->xfer_buf, io_u->xfer_buflen);
	else if (ddir_sync(io_u->ddir)) {
		if (msync(fmd->mmap_ptr, fmd->mmap_sz, MS_SYNC)) {
			io_u->error = errno;
			td_verror(td, io_u->error, "msync");
		}
	} else if (io_u->ddir == DDIR_TRIM) {
		int ret = do_io_u_trim(td, io_u);

		if (!ret)
			td_verror(td, io_u->error, "trim");
	}


	/*
	 * not really direct, but should drop the pages from the cache
	 */
	if (td->o.odirect && ddir_rw(io_u->ddir)) {
		if (msync(io_u->mmap_data, io_u->xfer_buflen, MS_SYNC) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "msync");
		}
		if (posix_madvise(io_u->mmap_data, io_u->xfer_buflen, POSIX_MADV_DONTNEED) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "madvise");
		}
	}

	return FIO_Q_COMPLETED;
}

static int fio_mmapio_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	if ((o->rw_min_bs & page_mask) &&
	    (o->odirect || o->fsync_blocks || o->fdatasync_blocks)) {
		log_err("fio: mmap options dictate a minimum block size of "
			"%llu bytes\n", (unsigned long long) page_size);
		return 1;
	}

	mmap_map_size = MMAP_TOTAL_SZ / o->nr_files;
	return 0;
}

static int fio_mmapio_open_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_mmap_data *fmd;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	fmd = calloc(1, sizeof(*fmd));
	if (!fmd) {
		int fio_unused __ret;
		__ret = generic_close_file(td, f);
		return 1;
	}

	FILE_SET_ENG_DATA(f, fmd);
	return 0;
}

static int fio_mmapio_close_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_mmap_data *fmd = FILE_ENG_DATA(f);

	FILE_SET_ENG_DATA(f, NULL);
	free(fmd);
	fio_file_clear_partial_mmap(f);

	return generic_close_file(td, f);
}

static struct ioengine_ops ioengine = {
	.name		= "mmap",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_mmapio_init,
	.prep		= fio_mmapio_prep,
	.queue		= fio_mmapio_queue,
	.open_file	= fio_mmapio_open_file,
	.close_file	= fio_mmapio_close_file,
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
