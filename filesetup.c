#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "fio.h"
#include "os.h"

/*
 * Check if the file exists and it's large enough.
 */
static int file_ok(struct thread_data *td, struct fio_file *f)
{
	struct stat st;

	if (td->filetype != FIO_TYPE_FILE)
		return 0;

	if (stat(f->file_name, &st) == -1)
		return 1;
	else if (st.st_size < (off_t) f->file_size)
		return 1;

	return 0;
}

static int create_file(struct thread_data *td, struct fio_file *f)
{
	unsigned long long left;
	unsigned int bs;
	char *b;
	int r;

	f->fd = open(f->file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (f->fd < 0) {
		td_verror(td, errno);
		return 1;
	}

	if (ftruncate(f->fd, f->file_size) == -1) {
		td_verror(td, errno);
		goto err;
	}

	if (posix_fallocate(f->fd, 0, f->file_size) < 0) {
		td_verror(td, errno);
		goto err;
	}

	b = malloc(td->max_bs[DDIR_WRITE]);
	memset(b, 0, td->max_bs[DDIR_WRITE]);

	left = f->file_size;
	while (left && !td->terminate) {
		bs = td->max_bs[DDIR_WRITE];
		if (bs > left)
			bs = left;

		r = write(f->fd, b, bs);

		if (r == (int) bs) {
			left -= bs;
			continue;
		} else {
			if (r < 0)
				td_verror(td, errno);
			else
				td_verror(td, EIO);

			break;
		}
	}

	if (td->terminate)
		unlink(f->file_name);
	else if (td->create_fsync)
		fsync(f->fd);

	free(b);
	close(f->fd);
	f->fd = -1;
	return 0;
err:
	close(f->fd);
	f->fd = -1;
	return 1;
}

static int create_files(struct thread_data *td)
{
	struct fio_file *f;
	int i, err, need_create;

	for_each_file(td, f, i)
		f->file_size = td->total_file_size / td->nr_files;

	/*
	 * unless specifically asked for overwrite, let normal io extend it
	 */
	if (!td->overwrite)
		return 0;

	need_create = 0;
	if (td->filetype == FIO_TYPE_FILE)
		for_each_file(td, f, i)
			need_create += file_ok(td, f);

	if (!need_create)
		return 0;

	if (!td->total_file_size) {
		log_err("Need size for create\n");
		td_verror(td, EINVAL);
		return 1;
	}

	temp_stall_ts = 1;
	fprintf(f_out, "%s: Laying out IO file(s) (%u x %LuMiB == %LuMiB)\n",
				td->name, td->nr_uniq_files,
				(td->total_file_size >> 20) / td->nr_uniq_files,
				td->total_file_size >> 20);

	err = 0;
	for_each_file(td, f, i) {
		/*
		 * Only unlink files that we created.
		 */
		f->unlink = 0;
		if (file_ok(td, f)) {
			f->unlink = td->unlink;
			err = create_file(td, f);
			if (err)
				break;
		}
	}

	temp_stall_ts = 0;
	return err;
}

static int file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat st;

	if (td->overwrite) {
		if (fstat(f->fd, &st) == -1) {
			td_verror(td, errno);
			return 1;
		}

		f->real_file_size = st.st_size;

		if (!f->file_size || f->file_size > f->real_file_size)
			f->file_size = f->real_file_size;
	}

	f->file_size = f->real_file_size - f->file_offset;
	return 0;
}

static int bdev_size(struct thread_data *td, struct fio_file *f)
{
	unsigned long long bytes;
	int r;

	r = blockdev_size(f->fd, &bytes);
	if (r) {
		td_verror(td, r);
		return 1;
	}

	f->real_file_size = bytes;

	/*
	 * no extend possibilities, so limit size to device size if too large
	 */
	if (!f->file_size || f->file_size > f->real_file_size)
		f->file_size = f->real_file_size;

	f->file_size -= f->file_offset;
	return 0;
}

static int get_file_size(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	if (td->filetype == FIO_TYPE_FILE)
		ret = file_size(td, f);
	else if (td->filetype == FIO_TYPE_BD)
		ret = bdev_size(td, f);
	else
		f->real_file_size = -1;

	if (ret)
		return ret;

	if (f->file_offset > f->real_file_size) {
		log_err("%s: offset extends end (%Lu > %Lu)\n", td->name, f->file_offset, f->real_file_size);
		return 1;
	}

	return 0;
}

int file_invalidate_cache(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	/*
	 * FIXME: add blockdev flushing too
	 */
	if (td->io_ops->flags & FIO_MMAPIO)
		ret = madvise(f->mmap, f->file_size, MADV_DONTNEED);
	else if (td->filetype == FIO_TYPE_FILE)
		ret = fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_DONTNEED);
	else if (td->filetype == FIO_TYPE_BD)
		ret = blockdev_invalidate_cache(f->fd);
	else if (td->filetype == FIO_TYPE_CHAR)
		ret = 0;

	if (ret < 0) {
		td_verror(td, errno);
		return 1;
	}

	return 0;
}

static int __setup_file_mmap(struct thread_data *td, struct fio_file *f)
{
	int flags;

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
		td_verror(td, errno);
		return 1;
	}

	if (td->invalidate_cache && file_invalidate_cache(td, f))
		return 1;

	if (td->sequential) {
		if (madvise(f->mmap, f->file_size, MADV_SEQUENTIAL) < 0) {
			td_verror(td, errno);
			return 1;
		}
	} else {
		if (madvise(f->mmap, f->file_size, MADV_RANDOM) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	return 0;
}

static int setup_files_mmap(struct thread_data *td)
{
	struct fio_file *f;
	int i, err = 0;

	for_each_file(td, f, i) {
		err = __setup_file_mmap(td, f);
		if (err)
			break;
	}

	return err;
}

static int __setup_file_plain(struct thread_data *td, struct fio_file *f)
{
	if (td->invalidate_cache && file_invalidate_cache(td, f))
		return 1;

	if (td->sequential) {
		if (fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_SEQUENTIAL) < 0) {
			td_verror(td, errno);
			return 1;
		}
	} else {
		if (fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_RANDOM) < 0) {
			td_verror(td, errno);
			return 1;
		}
	}

	return 0;
}

static int setup_files_plain(struct thread_data *td)
{
	struct fio_file *f;
	int i, err = 0;

	for_each_file(td, f, i) {
		err = __setup_file_plain(td, f);
		if (err)
			break;
	}

	return err;
}

static int setup_file(struct thread_data *td, struct fio_file *f)
{
	int flags = 0;

	if (td->odirect)
		flags |= OS_O_DIRECT;
	if (td->sync_io)
		flags |= O_SYNC;

	if (td_write(td) || td_rw(td)) {
		flags |= O_RDWR;

		if (td->filetype == FIO_TYPE_FILE) {
			if (!td->overwrite)
				flags |= O_TRUNC;

			flags |= O_CREAT;
		}

		f->fd = open(f->file_name, flags, 0600);
	} else {
		if (td->filetype == FIO_TYPE_CHAR)
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;

		f->fd = open(f->file_name, flags);
	}

	if (f->fd == -1) {
		td_verror(td, errno);
		return 1;
	}

	if (get_file_size(td, f))
		return 1;

	return 0;
}

int open_files(struct thread_data *td)
{
	struct fio_file *f;
	int i, err = 0;

	for_each_file(td, f, i) {
		err = setup_file(td, f);
		if (err)
			break;
	}

	if (!err)
		return 0;

	for_each_file(td, f, i) {
		if (f->fd != -1) {
			close(f->fd);
			f->fd = -1;
		}
	}

	return err;
}

int setup_files(struct thread_data *td)
{
	struct fio_file *f;
	int err, i;

	/*
	 * if ioengine defines a setup() method, it's responsible for
	 * setting up everything in the td->files[] area.
	 */
	if (td->io_ops->setup)
		return td->io_ops->setup(td);

	if (create_files(td))
		return 1;

	err = open_files(td);
	if (err)
		return err;

	/*
	 * Recalculate the total file size now that files are set up.
	 */
	td->total_file_size = 0;
	for_each_file(td, f, i)
		td->total_file_size += f->file_size;

	td->io_size = td->total_file_size;
	if (td->io_size == 0) {
		log_err("%s: no io blocks\n", td->name);
		td_verror(td, EINVAL);
		return 1;
	}

	if (!td->zone_size)
		td->zone_size = td->io_size;

	td->total_io_size = td->io_size * td->loops;

	if (td->io_ops->flags & FIO_MMAPIO)
		err = setup_files_mmap(td);
	else
		err = setup_files_plain(td);

	for_each_file(td, f, i) {
		if (f->fd != -1) {
			close(f->fd);
			f->fd = -1;
		}
	}

	return err;
}

void close_files(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	for_each_file(td, f, i) {
		if (!td->filename && f->unlink &&
		    td->filetype == FIO_TYPE_FILE) {
			unlink(f->file_name);
			free(f->file_name);
			f->file_name = NULL;
		}
		if (f->fd != -1) {
			close(f->fd);
			f->fd = -1;
		}
		if (f->mmap) {
			munmap(f->mmap, f->file_size);
			f->mmap = NULL;
		}
	}

	td->filename = NULL;
	free(td->files);
	td->files = NULL;
	td->nr_files = 0;
}
