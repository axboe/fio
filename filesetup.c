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

	if (f->filetype != FIO_TYPE_FILE ||
	    (td->io_ops->flags & FIO_DISKLESSIO))
		return 0;

	if (lstat(f->file_name, &st) == -1)
		return 1;

	/*
	 * if it's a special file, size is always ok for now
	 */
	if (S_ISCHR(st.st_mode) || S_ISBLK(st.st_mode))
		return 0;
	if (st.st_size < (off_t) f->file_size)
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
		td_verror(td, errno, "open");
		return 1;
	}

	if (ftruncate(f->fd, f->file_size) == -1) {
		td_verror(td, errno, "ftruncate");
		goto err;
	}

	if (posix_fallocate(f->fd, 0, f->file_size) < 0) {
		td_verror(td, errno, "posix_fallocate");
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
				td_verror(td, errno, "write");
			else
				td_verror(td, EIO, "write");

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
	int err, need_create, can_extend;
	unsigned int i;

	for_each_file(td, f, i) {
		if (f->filetype != FIO_TYPE_FILE)
			continue;

		f->file_size = td->total_file_size / td->nr_normal_files;
		f->file_offset = td->start_offset;
	}

	/*
	 * unless specifically asked for overwrite, let normal io extend it
	 */
	can_extend = !td->overwrite && !(td->io_ops->flags & FIO_NOEXTEND);
	if (can_extend)
		return 0;

	need_create = 0;
	for_each_file(td, f, i) {
		int file_there;

		if (f->filetype != FIO_TYPE_FILE)
			continue;

		file_there = !file_ok(td, f);

		if (file_there && td_write(td) && !td->overwrite) {
			unlink(f->file_name);
			file_there = 0;
		}

		need_create += !file_there;
	}

	if (!need_create)
		return 0;

	if (!td->total_file_size) {
		log_err("Need size for create\n");
		td_verror(td, EINVAL, "file_size");
		return 1;
	}

	temp_stall_ts = 1;
	fprintf(f_out, "%s: Laying out IO file(s) (%u x %LuMiB == %LuMiB)\n",
				td->name, td->nr_normal_files,
				(td->total_file_size >> 20) / td->nr_normal_files,
				td->total_file_size >> 20);

	err = 0;
	for_each_file(td, f, i) {
		/*
		 * Only unlink files that we created.
		 */
		f->flags &= ~FIO_FILE_UNLINK;
		if (file_ok(td, f)) {
			if (td->unlink)
				f->flags |= FIO_FILE_UNLINK;

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
			td_verror(td, errno, "fstat");
			return 1;
		}

		f->real_file_size = st.st_size;

		if (!f->file_size || f->file_size > f->real_file_size)
			f->file_size = f->real_file_size;
	} else
		f->real_file_size = f->file_size;

	return 0;
}

static int bdev_size(struct thread_data *td, struct fio_file *f)
{
	unsigned long long bytes;
	int r;

	r = blockdev_size(f->fd, &bytes);
	if (r) {
		td_verror(td, r, "blockdev_size");
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

	if (f->filetype == FIO_TYPE_FILE)
		ret = file_size(td, f);
	else if (f->filetype == FIO_TYPE_BD)
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

	if (td->odirect)
		return 0;

	/*
	 * FIXME: add blockdev flushing too
	 */
	if (f->mmap)
		ret = madvise(f->mmap, f->file_size, MADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_FILE) {
		ret = fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_DONTNEED);
	} else if (f->filetype == FIO_TYPE_BD) {
		ret = blockdev_invalidate_cache(f->fd);
	} else if (f->filetype == FIO_TYPE_CHAR)
		ret = 0;

	if (ret < 0) {
		td_verror(td, errno, "invalidate_cache");
		return 1;
	}

	return ret;
}

void generic_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	close(f->fd);
	f->fd = -1;
}

int generic_open_file(struct thread_data *td, struct fio_file *f)
{
	int flags = 0;

	if (td->odirect)
		flags |= OS_O_DIRECT;
	if (td->sync_io)
		flags |= O_SYNC;

	if (td_write(td) || td_rw(td)) {
		flags |= O_RDWR;

		if (f->filetype == FIO_TYPE_FILE)
			flags |= O_CREAT;

		f->fd = open(f->file_name, flags, 0600);
	} else {
		if (f->filetype == FIO_TYPE_CHAR)
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;

		f->fd = open(f->file_name, flags);
	}

	if (f->fd == -1) {
		int __e = errno;

		td_verror(td, __e, "open");
		if (__e == EINVAL && td->odirect)
			log_err("fio: destination does not support O_DIRECT\n");
		return 1;
	}

	if (get_file_size(td, f))
		goto err;

	if (td->invalidate_cache && file_invalidate_cache(td, f))
		goto err;

	if (!td_random(td)) {
		if (fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_SEQUENTIAL) < 0) {
			td_verror(td, errno, "fadvise");
			goto err;
		}
	} else {
		if (fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_RANDOM) < 0) {
			td_verror(td, errno, "fadvise");
			goto err;
		}
	}

	return 0;
err:
	close(f->fd);
	return 1;
}

int open_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;
	int err = 0;

	for_each_file(td, f, i) {
		err = td_io_open_file(td, f);
		if (err)
			break;

		if (td->open_files == td->nr_open_files)
			break;
	}

	if (!err)
		return 0;

	for_each_file(td, f, i)
		td_io_close_file(td, f);

	return err;
}

int setup_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;
	int err;

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
		td_verror(td, EINVAL, "total_file_size");
		return 1;
	}

	if (!td->zone_size)
		td->zone_size = td->io_size;

	td->total_io_size = td->io_size * td->loops;

	for_each_file(td, f, i)
		td_io_close_file(td, f);

	return err;
}

void close_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		if (!f->file_name && (f->flags & FIO_FILE_UNLINK) &&
		    f->filetype == FIO_TYPE_FILE) {
			unlink(f->file_name);
			free(f->file_name);
			f->file_name = NULL;
		}

		td_io_close_file(td, f);

		if (f->file_map)
			free(f->file_map);
	}

	td->filename = NULL;
	free(td->files);
	td->files = NULL;
	td->nr_files = 0;
}

static void get_file_type(struct fio_file *f)
{
	struct stat sb;

	f->filetype = FIO_TYPE_FILE;

	if (!lstat(f->file_name, &sb)) {
		if (S_ISBLK(sb.st_mode))
			f->filetype = FIO_TYPE_BD;
		else if (S_ISCHR(sb.st_mode))
			f->filetype = FIO_TYPE_CHAR;
	}
}

void add_file(struct thread_data *td, const char *fname)
{
	int cur_files = td->files_index;
	struct fio_file *f;

	td->files = realloc(td->files, (cur_files + 1) * sizeof(*f));

	f = &td->files[cur_files];
	memset(f, 0, sizeof(*f));
	f->fd = -1;
	f->file_name = strdup(fname);

	get_file_type(f);

	td->files_index++;
	if (f->filetype == FIO_TYPE_FILE)
		td->nr_normal_files++;
}

void get_file(struct fio_file *f)
{
	f->references++;
}

void put_file(struct thread_data *td, struct fio_file *f)
{
	if (!(f->flags & FIO_FILE_OPEN))
		return;

	assert(f->references);
	if (--f->references)
		return;

	if (td->io_ops->close_file)
		td->io_ops->close_file(td, f);
	td->nr_open_files--;
	f->flags &= ~FIO_FILE_OPEN;
}
