#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "fio.h"

static int root_warn;

static int extend_file(struct thread_data *td, struct fio_file *f)
{
	int r, new_layout = 0, unlink_file = 0, flags;
	unsigned long long left;
	unsigned int bs;
	char *b;

	if (read_only) {
		log_err("fio: refusing extend of file due to read-only\n");
		return 0;
	}

	/*
	 * check if we need to lay the file out complete again. fio
	 * does that for operations involving reads, or for writes
	 * where overwrite is set
	 */
	if (td_read(td) || (td_write(td) && td->o.overwrite))
		new_layout = 1;
	if (td_write(td) && !td->o.overwrite)
		unlink_file = 1;

	if ((unlink_file || new_layout) && (f->flags & FIO_FILE_EXISTS)) {
		if (unlink(f->file_name) < 0) {
			td_verror(td, errno, "unlink");
			return 1;
		}
	}

	flags = O_WRONLY | O_CREAT;
	if (new_layout)
		flags |= O_TRUNC;

	dprint(FD_FILE, "open file %s, flags %x\n", f->file_name, flags);
	f->fd = open(f->file_name, flags, 0644);
	if (f->fd < 0) {
		td_verror(td, errno, "open");
		return 1;
	}

	if (!new_layout)
		goto done;

	dprint(FD_FILE, "truncate file %s, size %llu\n", f->file_name,
							f->real_file_size);
	if (ftruncate(f->fd, f->real_file_size) == -1) {
		td_verror(td, errno, "ftruncate");
		goto err;
	}

	dprint(FD_FILE, "fallocate file %s, size %llu\n", f->file_name,
							f->real_file_size);
	if (posix_fallocate(f->fd, 0, f->real_file_size) < 0) {
		td_verror(td, errno, "posix_fallocate");
		goto err;
	}

	b = malloc(td->o.max_bs[DDIR_WRITE]);
	memset(b, 0, td->o.max_bs[DDIR_WRITE]);

	left = f->real_file_size;
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
done:
	close(f->fd);
	f->fd = -1;
	return 0;
err:
	close(f->fd);
	f->fd = -1;
	return 1;
}

static unsigned long long get_rand_file_size(struct thread_data *td)
{
	unsigned long long ret;
	long r;

	r = os_random_long(&td->file_size_state);
	ret = td->o.file_size_low + (unsigned long long) ((double) (td->o.file_size_high - td->o.file_size_low) * (r / (RAND_MAX + 1.0)));
	ret -= (ret % td->o.rw_min_bs);
	return ret;
}

static int file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat st;

	if (fstat(f->fd, &st) == -1) {
		td_verror(td, errno, "fstat");
		return 1;
	}

	f->real_file_size = st.st_size;
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
	return 0;
}

static int get_file_size(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	if (f->flags & FIO_SIZE_KNOWN)
		return 0;

	if (f->filetype == FIO_TYPE_FILE)
		ret = file_size(td, f);
	else if (f->filetype == FIO_TYPE_BD)
		ret = bdev_size(td, f);
	else
		f->real_file_size = -1;

	if (ret)
		return ret;

	if (f->file_offset > f->real_file_size) {
		log_err("%s: offset extends end (%Lu > %Lu)\n", td->o.name, f->file_offset, f->real_file_size);
		return 1;
	}

	f->flags |= FIO_SIZE_KNOWN;
	return 0;
}

int file_invalidate_cache(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	dprint(FD_IO, "invalidate cache (%d)\n", td->o.odirect);

	if (td->o.odirect)
		return 0;

	/*
	 * FIXME: add blockdev flushing too
	 */
	if (f->mmap)
		ret = madvise(f->mmap, f->io_size, MADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_FILE)
		ret = fadvise(f->fd, f->file_offset, f->io_size, POSIX_FADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_BD) {
		ret = blockdev_invalidate_cache(f->fd);
		if (ret < 0 && errno == EACCES && geteuid()) {
			if (!root_warn) {
				log_err("fio: only root may flush block devices. Cache flush bypassed!\n");
				root_warn = 1;
			}
			ret = 0;
		}
	} else if (f->filetype == FIO_TYPE_CHAR || f->filetype == FIO_TYPE_PIPE)
		ret = 0;

	if (ret < 0) {
		td_verror(td, errno, "invalidate_cache");
		return 1;
	}

	return ret;
}

void generic_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	dprint(FD_FILE, "fd close %s\n", f->file_name);
	close(f->fd);
	f->fd = -1;
}

int generic_open_file(struct thread_data *td, struct fio_file *f)
{
	int is_std = 0;
	int flags = 0;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (!strcmp(f->file_name, "-")) {
		if (td_rw(td)) {
			log_err("fio: can't read/write to stdin/out\n");
			return 1;
		}
		is_std = 1;

		/*
		 * move output logging to stderr, if we are writing to stdout
		 */
		if (td_write(td))
			f_out = stderr;
	}

	if (td->o.odirect)
		flags |= OS_O_DIRECT;
	if (td->o.sync_io)
		flags |= O_SYNC;
	if (f->filetype != FIO_TYPE_FILE)
		flags |= O_NOATIME;

open_again:
	if (td_write(td)) {
		assert(!read_only);

		flags |= O_RDWR;

		if (f->filetype == FIO_TYPE_FILE)
			flags |= O_CREAT;

		if (is_std)
			f->fd = dup(STDOUT_FILENO);
		else
			f->fd = open(f->file_name, flags, 0600);
	} else {
		if (f->filetype == FIO_TYPE_CHAR && !read_only)
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;

		if (is_std)
			f->fd = dup(STDIN_FILENO);
		else
			f->fd = open(f->file_name, flags);
	}

	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int __e = errno;

		if (errno == EPERM && (flags & O_NOATIME)) {
			flags &= ~O_NOATIME;
			goto open_again;
		}

		snprintf(buf, sizeof(buf) - 1, "open(%s)", f->file_name);

		td_verror(td, __e, buf);
	}

	if (get_file_size(td, f))
		goto err;

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

	dprint(FD_FILE, "open files\n");

	for_each_file(td, f, i) {
		err = td_io_open_file(td, f);
		if (err) {
			if (td->error == EMFILE) {
				log_err("fio: limited open files to: %d\n", td->nr_open_files);
				td->o.open_files = td->nr_open_files;
				err = 0;
				clear_error(td);
			}
			break;
		}

		if (td->o.open_files == td->nr_open_files)
			break;
	}

	if (!err)
		return 0;

	for_each_file(td, f, i)
		td_io_close_file(td, f);

	return err;
}

/*
 * open/close all files, so that ->real_file_size gets set
 */
static int get_file_sizes(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;
	int err = 0;

	for_each_file(td, f, i) {
		if (td->io_ops->open_file(td, f)) {
			if (td->error != ENOENT) {
				log_err("%s\n", td->verror);
				err = 1;
			}
			clear_error(td);
		} else {
			if (td->io_ops->close_file)
				td->io_ops->close_file(td, f);
		}

		if (f->real_file_size == -1ULL && td->o.size)
			f->real_file_size = td->o.size / td->o.nr_files;
	}

	return err;
}

/*
 * Open the files and setup files sizes, creating files if necessary.
 */
int setup_files(struct thread_data *td)
{
	unsigned long long total_size, extend_size;
	struct fio_file *f;
	unsigned int i;
	int err = 0, need_extend;

	dprint(FD_FILE, "setup files\n");

	/*
	 * if ioengine defines a setup() method, it's responsible for
	 * opening the files and setting f->real_file_size to indicate
	 * the valid range for that file.
	 */
	if (td->io_ops->setup)
		err = td->io_ops->setup(td);
	else
		err = get_file_sizes(td);

	if (err)
		return err;

	/*
	 * check sizes. if the files/devices do not exist and the size
	 * isn't passed to fio, abort.
	 */
	total_size = 0;
	for_each_file(td, f, i) {
		if (f->real_file_size == -1ULL)
			total_size = -1ULL;
		else
			total_size += f->real_file_size;
	}

	/*
	 * device/file sizes are zero and no size given, punt
	 */
	if ((!total_size || total_size == -1ULL) && !td->o.size &&
	    !(td->io_ops->flags & FIO_NOIO) && !td->o.fill_device) {
		log_err("%s: you need to specify size=\n", td->o.name);
		td_verror(td, EINVAL, "total_file_size");
		return 1;
	}

	/*
	 * now file sizes are known, so we can set ->io_size. if size= is
	 * not given, ->io_size is just equal to ->real_file_size. if size
	 * is given, ->io_size is size / nr_files.
	 */
	extend_size = total_size = 0;
	need_extend = 0;
	for_each_file(td, f, i) {
		f->file_offset = td->o.start_offset;

		if (!td->o.file_size_low) {
			/*
			 * no file size range given, file size is equal to
			 * total size divided by number of files. if that is
			 * zero, set it to the real file size.
			 */
			f->io_size = td->o.size / td->o.nr_files;
			if (!f->io_size)
				f->io_size = f->real_file_size - f->file_offset;
		} else if (f->real_file_size < td->o.file_size_low ||
			   f->real_file_size > td->o.file_size_high) {
			if (f->file_offset > td->o.file_size_low) 
				goto err_offset;
			/*
			 * file size given. if it's fixed, use that. if it's a
			 * range, generate a random size in-between.
			 */
			if (td->o.file_size_low == td->o.file_size_high)
				f->io_size = td->o.file_size_low - f->file_offset;
			else
				f->io_size = get_rand_file_size(td) - f->file_offset;
		} else
			f->io_size = f->real_file_size - f->file_offset;

		if (f->io_size == -1ULL)
			total_size = -1ULL;
		else
			total_size += f->io_size;

		if (f->filetype == FIO_TYPE_FILE &&
		    (f->io_size + f->file_offset) > f->real_file_size &&
		    !(td->io_ops->flags & FIO_DISKLESSIO)) {
			need_extend++;
			extend_size += (f->io_size + f->file_offset);
			f->flags |= FIO_FILE_EXTEND;
		}	
	}

	if (!td->o.size || td->o.size > total_size)
		td->o.size = total_size;

	/*
	 * See if we need to extend some files
	 */
	if (need_extend) {
		temp_stall_ts = 1;
		log_info("%s: Laying out IO file(s) (%u file(s) / %LuMiB)\n",
			td->o.name, need_extend, extend_size >> 20);

		for_each_file(td, f, i) {
			if (!(f->flags & FIO_FILE_EXTEND))
				continue;

			assert(f->filetype == FIO_TYPE_FILE);
			f->flags &= ~FIO_FILE_EXTEND;
			f->real_file_size = (f->io_size + f->file_offset);
			err = extend_file(td, f);
			if (err)
				break;
		}
		temp_stall_ts = 0;
	}

	if (err)
		return err;

	if (!td->o.zone_size)
		td->o.zone_size = td->o.size;

	/*
	 * iolog already set the total io size, if we read back
	 * stored entries.
	 */
	if (!td->o.read_iolog_file)
		td->total_io_size = td->o.size * td->o.loops;
	return 0;
err_offset:
	log_err("%s: you need to specify valid offset=\n", td->o.name);
	return 1;
}

int init_random_map(struct thread_data *td)
{
	unsigned long long blocks, num_maps;
	struct fio_file *f;
	unsigned int i;

	if (td->o.norandommap)
		return 0;

	for_each_file(td, f, i) {
		blocks = (f->real_file_size + td->o.rw_min_bs - 1) / (unsigned long long) td->o.rw_min_bs;
		num_maps = (blocks + BLOCKS_PER_MAP-1)/ (unsigned long long) BLOCKS_PER_MAP;
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

	dprint(FD_FILE, "close files\n");

	for_each_file(td, f, i) {
		if (td->o.unlink && f->filetype == FIO_TYPE_FILE)
			unlink(f->file_name);

		td_io_close_file(td, f);

		free(f->file_name);
		f->file_name = NULL;

		if (f->file_map) {
			free(f->file_map);
			f->file_map = NULL;
		}
	}

	td->o.filename = NULL;
	free(td->files);
	td->files = NULL;
	td->o.nr_files = 0;
}

static void get_file_type(struct fio_file *f)
{
	struct stat sb;

	if (!strcmp(f->file_name, "-"))
		f->filetype = FIO_TYPE_PIPE;
	else
		f->filetype = FIO_TYPE_FILE;

	if (!lstat(f->file_name, &sb)) {
		if (S_ISBLK(sb.st_mode))
			f->filetype = FIO_TYPE_BD;
		else if (S_ISCHR(sb.st_mode))
			f->filetype = FIO_TYPE_CHAR;
		else if (S_ISFIFO(sb.st_mode))
			f->filetype = FIO_TYPE_PIPE;
	}
}

int add_file(struct thread_data *td, const char *fname)
{
	int cur_files = td->files_index;
	char file_name[PATH_MAX];
	struct fio_file *f;
	int len = 0;

	dprint(FD_FILE, "add file %s\n", fname);

	td->files = realloc(td->files, (cur_files + 1) * sizeof(*f));

	f = &td->files[cur_files];
	memset(f, 0, sizeof(*f));
	f->fd = -1;

	/*
	 * init function, io engine may not be loaded yet
	 */
	if (td->io_ops && (td->io_ops->flags & FIO_DISKLESSIO))
		f->real_file_size = -1ULL;

	if (td->o.directory)
		len = sprintf(file_name, "%s/", td->o.directory);

	sprintf(file_name + len, "%s", fname);
	f->file_name = strdup(file_name);

	get_file_type(f);

	td->files_index++;
	if (f->filetype == FIO_TYPE_FILE)
		td->nr_normal_files++;

	return cur_files;
}

void get_file(struct fio_file *f)
{
	dprint(FD_FILE, "get file %s/%d\n", f->file_name, f->references);
	assert(f->flags & FIO_FILE_OPEN);
	f->references++;
}

void put_file(struct thread_data *td, struct fio_file *f)
{
	dprint(FD_FILE, "get put %s/%d\n", f->file_name, f->references);

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
		char buf[FIO_VERROR_SIZE];

		snprintf(buf, FIO_VERROR_SIZE - 1, "opendir(%s)", dirname);
		td_verror(td, errno, buf);
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
		if (!S_ISDIR(sb.st_mode))
			continue;

		if ((ret = recurse_dir(td, full_path)) != 0)
			break;
	}

	closedir(D);
	return ret;
}

int add_dir_files(struct thread_data *td, const char *path)
{
	int ret = recurse_dir(td, path);

	if (!ret)
		log_info("fio: opendir added %d files\n", td->o.nr_files);

	return ret;
}

void dup_files(struct thread_data *td, struct thread_data *org)
{
	struct fio_file *f;
	unsigned int i;
	size_t bytes;

	if (!org->files)
		return;

	bytes = org->files_index * sizeof(*f);
	td->files = malloc(bytes);
	memcpy(td->files, org->files, bytes);

	for_each_file(td, f, i) {
		if (f->file_name)
			f->file_name = strdup(f->file_name);
	}
}

/*
 * Returns the index that matches the filename, or -1 if not there
 */
int get_fileno(struct thread_data *td, const char *fname)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i)
		if (!strcmp(f->file_name, fname))
			return i;

	return -1;
}

/*
 * For log usage, where we add/open/close files automatically
 */
void free_release_files(struct thread_data *td)
{
	close_files(td);
	td->files_index = 0;
	td->nr_normal_files = 0;
}
