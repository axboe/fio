#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

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

	b = malloc(td->o.max_bs[DDIR_WRITE]);
	memset(b, 0, td->o.max_bs[DDIR_WRITE]);

	left = f->file_size;
	while (left && !td->terminate) {
		bs = td->o.max_bs[DDIR_WRITE];
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
	else if (td->o.create_fsync)
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

static unsigned long long set_rand_file_size(struct thread_data *td,
					     unsigned long long total_size)
{
	unsigned long long upper = total_size;
	unsigned long long ret;
	long r;

	if (upper > td->o.file_size_high)
		upper = td->o.file_size_high;
	else if (upper < td->o.file_size_low)
		return 0;
	else if (!upper)
		return 0;

	r = os_random_long(&td->file_size_state);
	ret = td->o.file_size_low + (unsigned long long) ((double) upper * (r / (RAND_MAX + 1.0)));
	ret -= (ret % td->o.rw_min_bs);
	if (ret > upper)
		ret = upper;
	return ret;
}

static int fill_file_size(struct thread_data *td, struct fio_file *f,
			  unsigned long long *file_size, int new_files)
{
	if (!td->o.file_size_low) {
		f->file_size = *file_size / new_files;
		f->real_file_size = f->file_size;
	} else {
		/*
		 * If we don't have enough space left for a file
		 * of the minimum size, bail.
		 */
		if (*file_size < td->o.file_size_low)
			return 1;

		f->file_size = set_rand_file_size(td, *file_size);
		f->real_file_size = f->file_size;
		*file_size -= f->file_size;
	}

	return 0;
}

static int create_files(struct thread_data *td)
{
	struct fio_file *f;
	int err, need_create, can_extend;
	unsigned long long total_file_size, local_file_size, create_size;
	unsigned int i, new_files;

	new_files = 0;
	total_file_size = td->o.size;
	for_each_file(td, f, i) {
		unsigned long long s;

		f->file_offset = td->o.start_offset;

		if (f->filetype != FIO_TYPE_FILE)
			continue;
		if (!total_file_size)
			continue;

		if (f->flags & FIO_FILE_EXISTS) {
			if ((f->file_size > td->o.size / td->o.nr_files) ||
			    !f->file_size)
				f->file_size = td->o.size / td->o.nr_files;

			s = f->file_size;
			if (s > total_file_size)
				s = total_file_size;

			total_file_size -= s;
		} else
			new_files++;
	}

	/*
	 * unless specifically asked for overwrite, let normal io extend it
	 */
	can_extend = !td->o.overwrite && !(td->io_ops->flags & FIO_NOEXTEND);
	if (can_extend) {
		for_each_file(td, f, i) {
			if (fill_file_size(td, f, &total_file_size, new_files)) {
				log_info("fio: limited to %d files\n", i);
				td->o.nr_files = i;
				break;
			}
		}

		return 0;
	}

	local_file_size = total_file_size;
	if (!local_file_size)
		local_file_size = -1;

	total_file_size = 0;
	need_create = 0;
	create_size = 0;
	for_each_file(td, f, i) {
		int file_there;

		if (f->filetype != FIO_TYPE_FILE)
			continue;
		if (f->flags & FIO_FILE_EXISTS) {
			total_file_size += f->file_size;
			continue;
		}

		if (fill_file_size(td, f, &local_file_size, new_files)) {
			log_info("fio: limited to %d files\n", i);
			new_files -= (td->o.nr_files - i);
			td->o.nr_files = i;
			break;
		}

		total_file_size += f->file_size;
		create_size += f->file_size;
		file_there = !file_ok(td, f);

		if (file_there && td_write(td) && !td->o.overwrite) {
			unlink(f->file_name);
			file_there = 0;
		}

		need_create += !file_there;
	}

	if (!need_create)
		return 0;

	if (!td->o.size && !total_file_size) {
		log_err("Need size for create\n");
		td_verror(td, EINVAL, "file_size");
		return 1;
	}

	temp_stall_ts = 1;
	log_info("%s: Laying out IO file(s) (%u files / %LuMiB)\n",
				td->o.name, new_files, create_size >> 20);

	err = 0;
	for_each_file(td, f, i) {
		/*
		 * Only unlink files that we created.
		 */
		f->flags &= ~FIO_FILE_UNLINK;
		if (file_ok(td, f)) {
			if (td->o.unlink)
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

	if (td->o.overwrite) {
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

	if (f->filetype == FIO_TYPE_FILE) {
		if (!(f->flags & FIO_FILE_EXISTS))
			ret = file_size(td, f);
	} else if (f->filetype == FIO_TYPE_BD)
		ret = bdev_size(td, f);
	else
		f->real_file_size = -1;

	if (ret)
		return ret;

	if (f->file_offset > f->real_file_size) {
		log_err("%s: offset extends end (%Lu > %Lu)\n", td->o.name, f->file_offset, f->real_file_size);
		return 1;
	}

	return 0;
}

int file_invalidate_cache(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	if (td->o.odirect)
		return 0;

	/*
	 * FIXME: add blockdev flushing too
	 */
	if (f->mmap)
		ret = madvise(f->mmap, f->file_size, MADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_FILE)
		ret = fadvise(f->fd, f->file_offset, f->file_size, POSIX_FADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_BD)
		ret = blockdev_invalidate_cache(f->fd);
	else if (f->filetype == FIO_TYPE_CHAR)
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

	if (td->o.odirect)
		flags |= OS_O_DIRECT;
	if (td->o.sync_io)
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
		if (__e == EINVAL && td->o.odirect)
			log_err("fio: destination does not support O_DIRECT\n");
		if (__e == EMFILE)
			log_err("fio: try reducing/setting openfiles (failed at %u of %u)\n", td->nr_open_files, td->o.nr_files);
		return 1;
	}

	if (get_file_size(td, f))
		goto err;

	if (td->o.invalidate_cache && file_invalidate_cache(td, f))
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

		if (td->o.open_files == td->nr_open_files)
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
	td->o.size = 0;
	for_each_file(td, f, i)
		td->o.size += f->file_size;

	td->io_size = td->o.size;
	if (td->io_size == 0) {
		log_err("%s: no io blocks\n", td->o.name);
		td_verror(td, EINVAL, "total_file_size");
		return 1;
	}

	if (!td->o.zone_size)
		td->o.zone_size = td->io_size;

	td->total_io_size = td->io_size * td->o.loops;

	for_each_file(td, f, i)
		td_io_close_file(td, f);

	return err;
}

int init_random_map(struct thread_data *td)
{
	int num_maps, blocks;
	struct fio_file *f;
	unsigned int i;

	if (td->o.norandommap)
		return 0;

	for_each_file(td, f, i) {
		blocks = (f->real_file_size + td->o.rw_min_bs - 1) / td->o.rw_min_bs;
		num_maps = (blocks + BLOCKS_PER_MAP-1)/ BLOCKS_PER_MAP;
		f->file_map = malloc(num_maps * sizeof(long));
		if (!f->file_map) {
			log_err("fio: failed allocating random map. If running a large number of jobs, try the 'norandommap' option\n");
			return 1;
		}
		f->num_maps = num_maps;
		memset(f->file_map, 0, num_maps * sizeof(long));
	}

	return 0;
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

		if (f->file_map) {
			free(f->file_map);
			f->file_map = NULL;
		}
	}

	td->o.filename = NULL;
	td->files = NULL;
	td->o.nr_files = 0;
}

static void get_file_type(struct fio_file *f)
{
	struct stat sb;

	f->filetype = FIO_TYPE_FILE;

	if (!lstat(f->file_name, &sb)) {
		f->flags |= FIO_FILE_EXISTS;

		if (S_ISBLK(sb.st_mode))
			f->filetype = FIO_TYPE_BD;
		else if (S_ISCHR(sb.st_mode))
			f->filetype = FIO_TYPE_CHAR;
		else {
			/*
			 * might as well do this here, and save a stat later on
			 */
			f->real_file_size = sb.st_size;
			f->file_size = f->real_file_size;
		}
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

	if (should_fsync(td) && td->o.fsync_on_close)
		fsync(f->fd);

	if (td->io_ops->close_file)
		td->io_ops->close_file(td, f);
	td->nr_open_files--;
	f->flags &= ~FIO_FILE_OPEN;
}

static int recurse_dir(struct thread_data *td, const char *dirname)
{
	struct dirent *dir;
	int ret = 0;
	DIR *D;

	D = opendir(dirname);
	if (!D) {
		td_verror(td, errno, "opendir");
		return 1;
	}

	while ((dir = readdir(D)) != NULL) {
		char full_path[PATH_MAX];
		struct stat sb;

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		sprintf(full_path, "%s/%s", dirname, dir->d_name);

		if (lstat(full_path, &sb) == -1) {
			if (errno != ENOENT) {
				td_verror(td, errno, "stat");
				return 1;
			}
		}

		if (S_ISREG(sb.st_mode)) {
			add_file(td, full_path);
			td->o.nr_files++;
			continue;
		}

		if ((ret = recurse_dir(td, full_path)) != 0)
			break;
	}

	closedir(D);
	return ret;
}

int add_dir_files(struct thread_data *td, const char *path)
{
	return recurse_dir(td, path);
}
