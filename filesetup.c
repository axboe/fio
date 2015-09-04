#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>

#include "fio.h"
#include "smalloc.h"
#include "filehash.h"
#include "options.h"
#include "os/os.h"
#include "hash.h"
#include "lib/axmap.h"

#ifdef CONFIG_LINUX_FALLOCATE
#include <linux/falloc.h>
#endif

static int root_warn;

static FLIST_HEAD(filename_list);

static inline void clear_error(struct thread_data *td)
{
	td->error = 0;
	td->verror[0] = '\0';
}

/*
 * Leaves f->fd open on success, caller must close
 */
static int extend_file(struct thread_data *td, struct fio_file *f)
{
	int r, new_layout = 0, unlink_file = 0, flags;
	unsigned long long left;
	unsigned int bs;
	char *b = NULL;

	if (read_only) {
		log_err("fio: refusing extend of file due to read-only\n");
		return 0;
	}

	/*
	 * check if we need to lay the file out complete again. fio
	 * does that for operations involving reads, or for writes
	 * where overwrite is set
	 */
	if (td_read(td) ||
	   (td_write(td) && td->o.overwrite && !td->o.file_append) ||
	    (td_write(td) && td->io_ops->flags & FIO_NOEXTEND))
		new_layout = 1;
	if (td_write(td) && !td->o.overwrite && !td->o.file_append)
		unlink_file = 1;

	if (unlink_file || new_layout) {
		dprint(FD_FILE, "layout unlink %s\n", f->file_name);
		if ((td_io_unlink_file(td, f) < 0) && (errno != ENOENT)) {
			td_verror(td, errno, "unlink");
			return 1;
		}
	}

	flags = O_WRONLY;
	if (td->o.allow_create)
		flags |= O_CREAT;
	if (new_layout)
		flags |= O_TRUNC;

#ifdef WIN32
	flags |= _O_BINARY;
#endif

	dprint(FD_FILE, "open file %s, flags %x\n", f->file_name, flags);
	f->fd = open(f->file_name, flags, 0644);
	if (f->fd < 0) {
		int err = errno;

		if (err == ENOENT && !td->o.allow_create)
			log_err("fio: file creation disallowed by "
					"allow_file_create=0\n");
		else
			td_verror(td, err, "open");
		return 1;
	}

#ifdef CONFIG_POSIX_FALLOCATE
	if (!td->o.fill_device) {
		switch (td->o.fallocate_mode) {
		case FIO_FALLOCATE_NONE:
			break;
		case FIO_FALLOCATE_POSIX:
			dprint(FD_FILE, "posix_fallocate file %s size %llu\n",
				 f->file_name,
				 (unsigned long long) f->real_file_size);

			r = posix_fallocate(f->fd, 0, f->real_file_size);
			if (r > 0) {
				log_err("fio: posix_fallocate fails: %s\n",
						strerror(r));
			}
			break;
#ifdef CONFIG_LINUX_FALLOCATE
		case FIO_FALLOCATE_KEEP_SIZE:
			dprint(FD_FILE,
				"fallocate(FALLOC_FL_KEEP_SIZE) "
				"file %s size %llu\n", f->file_name,
				(unsigned long long) f->real_file_size);

			r = fallocate(f->fd, FALLOC_FL_KEEP_SIZE, 0,
					f->real_file_size);
			if (r != 0)
				td_verror(td, errno, "fallocate");

			break;
#endif /* CONFIG_LINUX_FALLOCATE */
		default:
			log_err("fio: unknown fallocate mode: %d\n",
				td->o.fallocate_mode);
			assert(0);
		}
	}
#endif /* CONFIG_POSIX_FALLOCATE */

	if (!new_layout)
		goto done;

	/*
	 * The size will be -1ULL when fill_device is used, so don't truncate
	 * or fallocate this file, just write it
	 */
	if (!td->o.fill_device) {
		dprint(FD_FILE, "truncate file %s, size %llu\n", f->file_name,
					(unsigned long long) f->real_file_size);
		if (ftruncate(f->fd, f->real_file_size) == -1) {
			if (errno != EFBIG) {
				td_verror(td, errno, "ftruncate");
				goto err;
			}
		}
	}

	b = malloc(td->o.max_bs[DDIR_WRITE]);

	left = f->real_file_size;
	while (left && !td->terminate) {
		bs = td->o.max_bs[DDIR_WRITE];
		if (bs > left)
			bs = left;

		fill_io_buffer(td, b, bs, bs);

		r = write(f->fd, b, bs);

		if (r > 0) {
			left -= r;
			continue;
		} else {
			if (r < 0) {
				int __e = errno;

				if (__e == ENOSPC) {
					if (td->o.fill_device)
						break;
					log_info("fio: ENOSPC on laying out "
						 "file, stopping\n");
					break;
				}
				td_verror(td, errno, "write");
			} else
				td_verror(td, EIO, "write");

			break;
		}
	}

	if (td->terminate) {
		dprint(FD_FILE, "terminate unlink %s\n", f->file_name);
		td_io_unlink_file(td, f);
	} else if (td->o.create_fsync) {
		if (fsync(f->fd) < 0) {
			td_verror(td, errno, "fsync");
			goto err;
		}
	}
	if (td->o.fill_device && !td_write(td)) {
		fio_file_clear_size_known(f);
		if (td_io_get_file_size(td, f))
			goto err;
		if (f->io_size > f->real_file_size)
			f->io_size = f->real_file_size;
	}

	free(b);
done:
	return 0;
err:
	close(f->fd);
	f->fd = -1;
	if (b)
		free(b);
	return 1;
}

static int pre_read_file(struct thread_data *td, struct fio_file *f)
{
	int ret = 0, r, did_open = 0, old_runstate;
	unsigned long long left;
	unsigned int bs;
	char *b;

	if (td->io_ops->flags & FIO_PIPEIO)
		return 0;

	if (!fio_file_open(f)) {
		if (td->io_ops->open_file(td, f)) {
			log_err("fio: cannot pre-read, failed to open file\n");
			return 1;
		}
		did_open = 1;
	}

	old_runstate = td_bump_runstate(td, TD_PRE_READING);

	bs = td->o.max_bs[DDIR_READ];
	b = malloc(bs);
	memset(b, 0, bs);

	if (lseek(f->fd, f->file_offset, SEEK_SET) < 0) {
		td_verror(td, errno, "lseek");
		log_err("fio: failed to lseek pre-read file\n");
		ret = 1;
		goto error;
	}

	left = f->io_size;

	while (left && !td->terminate) {
		if (bs > left)
			bs = left;

		r = read(f->fd, b, bs);

		if (r == (int) bs) {
			left -= bs;
			continue;
		} else {
			td_verror(td, EIO, "pre_read");
			break;
		}
	}

error:
	td_restore_runstate(td, old_runstate);

	if (did_open)
		td->io_ops->close_file(td, f);

	free(b);
	return ret;
}

static unsigned long long get_rand_file_size(struct thread_data *td)
{
	unsigned long long ret, sized;
	uint64_t frand_max;
	unsigned long r;

	frand_max = rand_max(&td->file_size_state);
	r = __rand(&td->file_size_state);
	sized = td->o.file_size_high - td->o.file_size_low;
	ret = (unsigned long long) ((double) sized * (r / (frand_max + 1.0)));
	ret += td->o.file_size_low;
	ret -= (ret % td->o.rw_min_bs);
	return ret;
}

static int file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat st;

	if (stat(f->file_name, &st) == -1) {
		td_verror(td, errno, "fstat");
		return 1;
	}

	f->real_file_size = st.st_size;
	return 0;
}

static int bdev_size(struct thread_data *td, struct fio_file *f)
{
	unsigned long long bytes = 0;
	int r;

	if (td->io_ops->open_file(td, f)) {
		log_err("fio: failed opening blockdev %s for size check\n",
			f->file_name);
		return 1;
	}

	r = blockdev_size(f, &bytes);
	if (r) {
		td_verror(td, r, "blockdev_size");
		goto err;
	}

	if (!bytes) {
		log_err("%s: zero sized block device?\n", f->file_name);
		goto err;
	}

	f->real_file_size = bytes;
	td->io_ops->close_file(td, f);
	return 0;
err:
	td->io_ops->close_file(td, f);
	return 1;
}

static int char_size(struct thread_data *td, struct fio_file *f)
{
#ifdef FIO_HAVE_CHARDEV_SIZE
	unsigned long long bytes = 0;
	int r;

	if (td->io_ops->open_file(td, f)) {
		log_err("fio: failed opening blockdev %s for size check\n",
			f->file_name);
		return 1;
	}

	r = chardev_size(f, &bytes);
	if (r) {
		td_verror(td, r, "chardev_size");
		goto err;
	}

	if (!bytes) {
		log_err("%s: zero sized char device?\n", f->file_name);
		goto err;
	}

	f->real_file_size = bytes;
	td->io_ops->close_file(td, f);
	return 0;
err:
	td->io_ops->close_file(td, f);
	return 1;
#else
	f->real_file_size = -1ULL;
	return 0;
#endif
}

static int get_file_size(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;

	if (fio_file_size_known(f))
		return 0;

	if (f->filetype == FIO_TYPE_FILE)
		ret = file_size(td, f);
	else if (f->filetype == FIO_TYPE_BD)
		ret = bdev_size(td, f);
	else if (f->filetype == FIO_TYPE_CHAR)
		ret = char_size(td, f);
	else
		f->real_file_size = -1;

	if (ret)
		return ret;

	if (f->file_offset > f->real_file_size) {
		log_err("%s: offset extends end (%llu > %llu)\n", td->o.name,
					(unsigned long long) f->file_offset,
					(unsigned long long) f->real_file_size);
		return 1;
	}

	fio_file_set_size_known(f);
	return 0;
}

static int __file_invalidate_cache(struct thread_data *td, struct fio_file *f,
				   unsigned long long off,
				   unsigned long long len)
{
	int ret = 0;

#ifdef CONFIG_ESX
	return 0;
#endif

	if (len == -1ULL)
		len = f->io_size;
	if (off == -1ULL)
		off = f->file_offset;

	if (len == -1ULL || off == -1ULL)
		return 0;

	dprint(FD_IO, "invalidate cache %s: %llu/%llu\n", f->file_name, off,
								len);

	if (td->io_ops->invalidate)
		ret = td->io_ops->invalidate(td, f);
	else if (f->filetype == FIO_TYPE_FILE)
		ret = posix_fadvise(f->fd, off, len, POSIX_FADV_DONTNEED);
	else if (f->filetype == FIO_TYPE_BD) {
		int retry_count = 0;

		ret = blockdev_invalidate_cache(f);
		while (ret < 0 && errno == EAGAIN && retry_count++ < 25) {
			/*
			 * Linux multipath devices reject ioctl while
			 * the maps are being updated. That window can
			 * last tens of milliseconds; we'll try up to
			 * a quarter of a second.
			 */
			usleep(10000);
			ret = blockdev_invalidate_cache(f);
		}
		if (ret < 0 && errno == EACCES && geteuid()) {
			if (!root_warn) {
				log_err("fio: only root may flush block "
					"devices. Cache flush bypassed!\n");
				root_warn = 1;
			}
			ret = 0;
		}
	} else if (f->filetype == FIO_TYPE_CHAR || f->filetype == FIO_TYPE_PIPE)
		ret = 0;

	/*
	 * Cache flushing isn't a fatal condition, and we know it will
	 * happen on some platforms where we don't have the proper
	 * function to flush eg block device caches. So just warn and
	 * continue on our way.
	 */
	if (ret) {
		log_info("fio: cache invalidation of %s failed: %s\n", f->file_name, strerror(errno));
		ret = 0;
	}

	return 0;

}

int file_invalidate_cache(struct thread_data *td, struct fio_file *f)
{
	if (!fio_file_open(f))
		return 0;

	return __file_invalidate_cache(td, f, -1ULL, -1ULL);
}

int generic_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	int ret = 0;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	remove_file_hash(f);

	if (close(f->fd) < 0)
		ret = errno;

	f->fd = -1;

	if (f->shadow_fd != -1) {
		close(f->shadow_fd);
		f->shadow_fd = -1;
	}

	f->engine_data = 0;
	return ret;
}

int file_lookup_open(struct fio_file *f, int flags)
{
	struct fio_file *__f;
	int from_hash;

	__f = lookup_file_hash(f->file_name);
	if (__f) {
		dprint(FD_FILE, "found file in hash %s\n", f->file_name);
		/*
		 * racy, need the __f->lock locked
		 */
		f->lock = __f->lock;
		from_hash = 1;
	} else {
		dprint(FD_FILE, "file not found in hash %s\n", f->file_name);
		from_hash = 0;
	}

#ifdef WIN32
	flags |= _O_BINARY;
#endif

	f->fd = open(f->file_name, flags, 0600);
	return from_hash;
}

static int file_close_shadow_fds(struct thread_data *td)
{
	struct fio_file *f;
	int num_closed = 0;
	unsigned int i;

	for_each_file(td, f, i) {
		if (f->shadow_fd == -1)
			continue;

		close(f->shadow_fd);
		f->shadow_fd = -1;
		num_closed++;
	}

	return num_closed;
}

int generic_open_file(struct thread_data *td, struct fio_file *f)
{
	int is_std = 0;
	int flags = 0;
	int from_hash = 0;

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

	if (td_trim(td))
		goto skip_flags;
	if (td->o.odirect)
		flags |= OS_O_DIRECT;
	if (td->o.oatomic) {
		if (!FIO_O_ATOMIC) {
			td_verror(td, EINVAL, "OS does not support atomic IO");
			return 1;
		}
		flags |= OS_O_DIRECT | FIO_O_ATOMIC;
	}
	if (td->o.sync_io)
		flags |= O_SYNC;
	if (td->o.create_on_open && td->o.allow_create)
		flags |= O_CREAT;
skip_flags:
	if (f->filetype != FIO_TYPE_FILE)
		flags |= FIO_O_NOATIME;

open_again:
	if (td_write(td)) {
		if (!read_only)
			flags |= O_RDWR;

		if (f->filetype == FIO_TYPE_FILE && td->o.allow_create)
			flags |= O_CREAT;

		if (is_std)
			f->fd = dup(STDOUT_FILENO);
		else
			from_hash = file_lookup_open(f, flags);
	} else if (td_read(td)) {
		if (f->filetype == FIO_TYPE_CHAR && !read_only)
			flags |= O_RDWR;
		else
			flags |= O_RDONLY;

		if (is_std)
			f->fd = dup(STDIN_FILENO);
		else
			from_hash = file_lookup_open(f, flags);
	} else { //td trim
		flags |= O_RDWR;
		from_hash = file_lookup_open(f, flags);
	}

	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int __e = errno;

		if (__e == EPERM && (flags & FIO_O_NOATIME)) {
			flags &= ~FIO_O_NOATIME;
			goto open_again;
		}
		if (__e == EMFILE && file_close_shadow_fds(td))
			goto open_again;

		snprintf(buf, sizeof(buf), "open(%s)", f->file_name);

		if (__e == EINVAL && (flags & OS_O_DIRECT)) {
			log_err("fio: looks like your file system does not " \
				"support direct=1/buffered=0\n");
		}

		td_verror(td, __e, buf);
		return 1;
	}

	if (!from_hash && f->fd != -1) {
		if (add_file_hash(f)) {
			int fio_unused ret;

			/*
			 * Stash away descriptor for later close. This is to
			 * work-around a "feature" on Linux, where a close of
			 * an fd that has been opened for write will trigger
			 * udev to call blkid to check partitions, fs id, etc.
			 * That pollutes the device cache, which can slow down
			 * unbuffered accesses.
			 */
			if (f->shadow_fd == -1)
				f->shadow_fd = f->fd;
			else {
				/*
			 	 * OK to ignore, we haven't done anything
				 * with it
				 */
				ret = generic_close_file(td, f);
			}
			goto open_again;
		}
	}

	return 0;
}

int generic_get_file_size(struct thread_data *td, struct fio_file *f)
{
	return get_file_size(td, f);
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
		dprint(FD_FILE, "get file size for %p/%d/%p\n", f, i,
								f->file_name);

		if (td_io_get_file_size(td, f)) {
			if (td->error != ENOENT) {
				log_err("%s\n", td->verror);
				err = 1;
				break;
			}
			clear_error(td);
		}

		if (f->real_file_size == -1ULL && td->o.size)
			f->real_file_size = td->o.size / td->o.nr_files;
	}

	return err;
}

struct fio_mount {
	struct flist_head list;
	const char *base;
	char __base[256];
	unsigned int key;
};

/*
 * Get free number of bytes for each file on each unique mount.
 */
static unsigned long long get_fs_free_counts(struct thread_data *td)
{
	struct flist_head *n, *tmp;
	unsigned long long ret = 0;
	struct fio_mount *fm;
	FLIST_HEAD(list);
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		struct stat sb;
		char buf[256];

		if (f->filetype == FIO_TYPE_BD || f->filetype == FIO_TYPE_CHAR) {
			if (f->real_file_size != -1ULL)
				ret += f->real_file_size;
			continue;
		} else if (f->filetype != FIO_TYPE_FILE)
			continue;

		buf[255] = '\0';
		strncpy(buf, f->file_name, 255);

		if (stat(buf, &sb) < 0) {
			if (errno != ENOENT)
				break;
			strcpy(buf, ".");
			if (stat(buf, &sb) < 0)
				break;
		}

		fm = NULL;
		flist_for_each(n, &list) {
			fm = flist_entry(n, struct fio_mount, list);
			if (fm->key == sb.st_dev)
				break;

			fm = NULL;
		}

		if (fm)
			continue;

		fm = calloc(1, sizeof(*fm));
		strncpy(fm->__base, buf, sizeof(fm->__base) - 1);
		fm->base = basename(fm->__base);
		fm->key = sb.st_dev;
		flist_add(&fm->list, &list);
	}

	flist_for_each_safe(n, tmp, &list) {
		unsigned long long sz;

		fm = flist_entry(n, struct fio_mount, list);
		flist_del(&fm->list);

		sz = get_fs_free_size(fm->base);
		if (sz && sz != -1ULL)
			ret += sz;

		free(fm);
	}

	return ret;
}

uint64_t get_start_offset(struct thread_data *td, struct fio_file *f)
{
	struct thread_options *o = &td->o;

	if (o->file_append && f->filetype == FIO_TYPE_FILE)
		return f->real_file_size;

	return td->o.start_offset +
		td->subjob_number * td->o.offset_increment;
}

/*
 * Open the files and setup files sizes, creating files if necessary.
 */
int setup_files(struct thread_data *td)
{
	unsigned long long total_size, extend_size;
	struct thread_options *o = &td->o;
	struct fio_file *f;
	unsigned int i, nr_fs_extra = 0;
	int err = 0, need_extend;
	int old_state;
	const unsigned int bs = td_min_bs(td);
	uint64_t fs = 0;

	dprint(FD_FILE, "setup files\n");

	old_state = td_bump_runstate(td, TD_SETTING_UP);

	if (o->read_iolog_file)
		goto done;

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
		goto err_out;

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

	if (o->fill_device)
		td->fill_device_size = get_fs_free_counts(td);

	/*
	 * device/file sizes are zero and no size given, punt
	 */
	if ((!total_size || total_size == -1ULL) && !o->size &&
	    !(td->io_ops->flags & FIO_NOIO) && !o->fill_device &&
	    !(o->nr_files && (o->file_size_low || o->file_size_high))) {
		log_err("%s: you need to specify size=\n", o->name);
		td_verror(td, EINVAL, "total_file_size");
		goto err_out;
	}

	/*
	 * Calculate per-file size and potential extra size for the
	 * first files, if needed.
	 */
	if (!o->file_size_low && o->nr_files) {
		uint64_t all_fs;

		fs = o->size / o->nr_files;
		all_fs = fs * o->nr_files;

		if (all_fs < o->size)
			nr_fs_extra = (o->size - all_fs) / bs;
	}

	/*
	 * now file sizes are known, so we can set ->io_size. if size= is
	 * not given, ->io_size is just equal to ->real_file_size. if size
	 * is given, ->io_size is size / nr_files.
	 */
	extend_size = total_size = 0;
	need_extend = 0;
	for_each_file(td, f, i) {
		f->file_offset = get_start_offset(td, f);

		if (!o->file_size_low) {
			/*
			 * no file size range given, file size is equal to
			 * total size divided by number of files. If that is
			 * zero, set it to the real file size. If the size
			 * doesn't divide nicely with the min blocksize,
			 * make the first files bigger.
			 */
			f->io_size = fs;
			if (nr_fs_extra) {
				nr_fs_extra--;
				f->io_size += bs;
			}

			if (!f->io_size)
				f->io_size = f->real_file_size - f->file_offset;
		} else if (f->real_file_size < o->file_size_low ||
			   f->real_file_size > o->file_size_high) {
			if (f->file_offset > o->file_size_low)
				goto err_offset;
			/*
			 * file size given. if it's fixed, use that. if it's a
			 * range, generate a random size in-between.
			 */
			if (o->file_size_low == o->file_size_high)
				f->io_size = o->file_size_low - f->file_offset;
			else {
				f->io_size = get_rand_file_size(td)
						- f->file_offset;
			}
		} else
			f->io_size = f->real_file_size - f->file_offset;

		if (f->io_size == -1ULL)
			total_size = -1ULL;
		else {
                        if (o->size_percent)
                                f->io_size = (f->io_size * o->size_percent) / 100;
			total_size += f->io_size;
		}

		if (f->filetype == FIO_TYPE_FILE &&
		    (f->io_size + f->file_offset) > f->real_file_size &&
		    !(td->io_ops->flags & FIO_DISKLESSIO)) {
			if (!o->create_on_open) {
				need_extend++;
				extend_size += (f->io_size + f->file_offset);
			} else
				f->real_file_size = f->io_size + f->file_offset;
			fio_file_set_extend(f);
		}
	}

	if (td->o.block_error_hist) {
		int len;

		assert(td->o.nr_files == 1);	/* checked in fixup_options */
		f = td->files[0];
		len = f->io_size / td->o.bs[DDIR_TRIM];
		if (len > MAX_NR_BLOCK_INFOS || len <= 0) {
			log_err("fio: cannot calculate block histogram with "
				"%d trim blocks, maximum %d\n",
				len, MAX_NR_BLOCK_INFOS);
			td_verror(td, EINVAL, "block_error_hist");
			goto err_out;
		}

		td->ts.nr_block_infos = len;
		for (int i = 0; i < len; i++)
			td->ts.block_infos[i] =
				BLOCK_INFO(0, BLOCK_STATE_UNINIT);
	} else
		td->ts.nr_block_infos = 0;

	if (!o->size || (total_size && o->size > total_size))
		o->size = total_size;

	if (o->size < td_min_bs(td)) {
		log_err("fio: blocksize too large for data set\n");
		goto err_out;
	}

	/*
	 * See if we need to extend some files
	 */
	if (need_extend) {
		temp_stall_ts = 1;
		if (output_format == FIO_OUTPUT_NORMAL)
			log_info("%s: Laying out IO file(s) (%u file(s) /"
				 " %lluMB)\n", o->name, need_extend,
					extend_size >> 20);

		for_each_file(td, f, i) {
			unsigned long long old_len = -1ULL, extend_len = -1ULL;

			if (!fio_file_extend(f))
				continue;

			assert(f->filetype == FIO_TYPE_FILE);
			fio_file_clear_extend(f);
			if (!o->fill_device) {
				old_len = f->real_file_size;
				extend_len = f->io_size + f->file_offset -
						old_len;
			}
			f->real_file_size = (f->io_size + f->file_offset);
			err = extend_file(td, f);
			if (err)
				break;

			err = __file_invalidate_cache(td, f, old_len,
								extend_len);

			/*
			 * Shut up static checker
			 */
			if (f->fd != -1)
				close(f->fd);

			f->fd = -1;
			if (err)
				break;
		}
		temp_stall_ts = 0;
	}

	if (err)
		goto err_out;

	if (!o->zone_size)
		o->zone_size = o->size;

	/*
	 * iolog already set the total io size, if we read back
	 * stored entries.
	 */
	if (!o->read_iolog_file) {
		if (o->io_limit)
			td->total_io_size = o->io_limit * o->loops;
		else
			td->total_io_size = o->size * o->loops;
	}

done:
	if (o->create_only)
		td->done = 1;

	td_restore_runstate(td, old_state);
	return 0;
err_offset:
	log_err("%s: you need to specify valid offset=\n", o->name);
err_out:
	td_restore_runstate(td, old_state);
	return 1;
}

int pre_read_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	dprint(FD_FILE, "pre_read files\n");

	for_each_file(td, f, i) {
		pre_read_file(td, f);
	}

	return 1;
}

static int __init_rand_distribution(struct thread_data *td, struct fio_file *f)
{
	unsigned int range_size, seed;
	unsigned long nranges;
	uint64_t fsize;

	range_size = min(td->o.min_bs[DDIR_READ], td->o.min_bs[DDIR_WRITE]);
	fsize = min(f->real_file_size, f->io_size);

	nranges = (fsize + range_size - 1) / range_size;

	seed = jhash(f->file_name, strlen(f->file_name), 0) * td->thread_number;
	if (!td->o.rand_repeatable)
		seed = td->rand_seeds[4];

	if (td->o.random_distribution == FIO_RAND_DIST_ZIPF)
		zipf_init(&f->zipf, nranges, td->o.zipf_theta.u.f, seed);
	else if (td->o.random_distribution == FIO_RAND_DIST_PARETO)
		pareto_init(&f->zipf, nranges, td->o.pareto_h.u.f, seed);
	else if (td->o.random_distribution == FIO_RAND_DIST_GAUSS)
		gauss_init(&f->gauss, nranges, td->o.gauss_dev.u.f, seed);

	return 1;
}

static int init_rand_distribution(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;
	int state;

	if (td->o.random_distribution == FIO_RAND_DIST_RANDOM)
		return 0;

	state = td_bump_runstate(td, TD_SETTING_UP);

	for_each_file(td, f, i)
		__init_rand_distribution(td, f);

	td_restore_runstate(td, state);

	return 1;
}

/*
 * Check if the number of blocks exceeds the randomness capability of
 * the selected generator. Tausworthe is 32-bit, the others are fullly
 * 64-bit capable.
 */
static int check_rand_gen_limits(struct thread_data *td, struct fio_file *f,
				 uint64_t blocks)
{
	if (blocks <= FRAND32_MAX)
		return 0;
	if (td->o.random_generator != FIO_RAND_GEN_TAUSWORTHE)
		return 0;

	/*
	 * If the user hasn't specified a random generator, switch
	 * to tausworthe64 with informational warning. If the user did
	 * specify one, just warn.
	 */
	log_info("fio: file %s exceeds 32-bit tausworthe random generator.\n",
			f->file_name);

	if (!fio_option_is_set(&td->o, random_generator)) {
		log_info("fio: Switching to tausworthe64. Use the "
			 "random_generator= option to get rid of this "
			 " warning.\n");
		td->o.random_generator = FIO_RAND_GEN_TAUSWORTHE64;
		return 0;
	}

	/*
	 * Just make this information to avoid breaking scripts.
	 */
	log_info("fio: Use the random_generator= option to switch to lfsr or "
			 "tausworthe64.\n");
	return 0;
}

int init_random_map(struct thread_data *td)
{
	unsigned long long blocks;
	struct fio_file *f;
	unsigned int i;

	if (init_rand_distribution(td))
		return 0;
	if (!td_random(td))
		return 0;

	for_each_file(td, f, i) {
		uint64_t fsize = min(f->real_file_size, f->io_size);

		blocks = fsize / (unsigned long long) td->o.rw_min_bs;

		if (check_rand_gen_limits(td, f, blocks))
			return 1;

		if (td->o.random_generator == FIO_RAND_GEN_LFSR) {
			unsigned long seed;

			seed = td->rand_seeds[FIO_RAND_BLOCK_OFF];

			if (!lfsr_init(&f->lfsr, blocks, seed, 0)) {
				fio_file_set_lfsr(f);
				continue;
			}
		} else if (!td->o.norandommap) {
			f->io_axmap = axmap_new(blocks);
			if (f->io_axmap) {
				fio_file_set_axmap(f);
				continue;
			}
		} else if (td->o.norandommap)
			continue;

		if (!td->o.softrandommap) {
			log_err("fio: failed allocating random map. If running"
				" a large number of jobs, try the 'norandommap'"
				" option or set 'softrandommap'. Or give"
				" a larger --alloc-size to fio.\n");
			return 1;
		}

		log_info("fio: file %s failed allocating random map. Running "
			 "job without.\n", f->file_name);
	}

	return 0;
}

void close_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		if (fio_file_open(f))
			td_io_close_file(td, f);
	}
}

void close_and_free_files(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	dprint(FD_FILE, "close files\n");

	for_each_file(td, f, i) {
		if (td->o.unlink && f->filetype == FIO_TYPE_FILE) {
			dprint(FD_FILE, "free unlink %s\n", f->file_name);
			td_io_unlink_file(td, f);
		}

		if (fio_file_open(f))
			td_io_close_file(td, f);

		remove_file_hash(f);

		if (td->o.unlink && f->filetype == FIO_TYPE_FILE) {
			dprint(FD_FILE, "free unlink %s\n", f->file_name);
			td_io_unlink_file(td, f);
		}

		sfree(f->file_name);
		f->file_name = NULL;
		if (fio_file_axmap(f)) {
			axmap_free(f->io_axmap);
			f->io_axmap = NULL;
		}
		sfree(f);
	}

	td->o.filename = NULL;
	free(td->files);
	free(td->file_locks);
	td->files_index = 0;
	td->files = NULL;
	td->file_locks = NULL;
	td->o.file_lock_mode = FILE_LOCK_NONE;
	td->o.nr_files = 0;
}

static void get_file_type(struct fio_file *f)
{
	struct stat sb;

	if (!strcmp(f->file_name, "-"))
		f->filetype = FIO_TYPE_PIPE;
	else
		f->filetype = FIO_TYPE_FILE;

	/* \\.\ is the device namespace in Windows, where every file is
	 * a block device */
	if (strncmp(f->file_name, "\\\\.\\", 4) == 0)
		f->filetype = FIO_TYPE_BD;

	if (!stat(f->file_name, &sb)) {
		if (S_ISBLK(sb.st_mode))
			f->filetype = FIO_TYPE_BD;
		else if (S_ISCHR(sb.st_mode))
			f->filetype = FIO_TYPE_CHAR;
		else if (S_ISFIFO(sb.st_mode))
			f->filetype = FIO_TYPE_PIPE;
	}
}

static int __is_already_allocated(const char *fname)
{
	struct flist_head *entry;
	char *filename;

	if (flist_empty(&filename_list))
		return 0;

	flist_for_each(entry, &filename_list) {
		filename = flist_entry(entry, struct file_name, list)->filename;

		if (strcmp(filename, fname) == 0)
			return 1;
	}

	return 0;
}

static int is_already_allocated(const char *fname)
{
	int ret;

	fio_file_hash_lock();
	ret = __is_already_allocated(fname);
	fio_file_hash_unlock();
	return ret;
}

static void set_already_allocated(const char *fname)
{
	struct file_name *fn;

	fn = malloc(sizeof(struct file_name));
	fn->filename = strdup(fname);

	fio_file_hash_lock();
	if (!__is_already_allocated(fname)) {
		flist_add_tail(&fn->list, &filename_list);
		fn = NULL;
	}
	fio_file_hash_unlock();

	if (fn) {
		free(fn->filename);
		free(fn);
	}
}


static void free_already_allocated(void)
{
	struct flist_head *entry, *tmp;
	struct file_name *fn;

	if (flist_empty(&filename_list))
		return;

	fio_file_hash_lock();
	flist_for_each_safe(entry, tmp, &filename_list) {
		fn = flist_entry(entry, struct file_name, list);
		free(fn->filename);
		flist_del(&fn->list);
		free(fn);
	}

	fio_file_hash_unlock();
}

static struct fio_file *alloc_new_file(struct thread_data *td)
{
	struct fio_file *f;

	f = smalloc(sizeof(*f));
	if (!f) {
		log_err("fio: smalloc OOM\n");
		assert(0);
		return NULL;
	}

	f->fd = -1;
	f->shadow_fd = -1;
	fio_file_reset(td, f);
	return f;
}

int add_file(struct thread_data *td, const char *fname, int numjob, int inc)
{
	int cur_files = td->files_index;
	char file_name[PATH_MAX];
	struct fio_file *f;
	int len = 0;

	dprint(FD_FILE, "add file %s\n", fname);

	if (td->o.directory)
		len = set_name_idx(file_name, PATH_MAX, td->o.directory, numjob);

	sprintf(file_name + len, "%s", fname);

	/* clean cloned siblings using existing files */
	if (numjob && is_already_allocated(file_name))
		return 0;

	f = alloc_new_file(td);

	if (td->files_size <= td->files_index) {
		unsigned int new_size = td->o.nr_files + 1;

		dprint(FD_FILE, "resize file array to %d files\n", new_size);

		td->files = realloc(td->files, new_size * sizeof(f));
		if (td->files == NULL) {
			log_err("fio: realloc OOM\n");
			assert(0);
		}
		if (td->o.file_lock_mode != FILE_LOCK_NONE) {
			td->file_locks = realloc(td->file_locks, new_size);
			if (!td->file_locks) {
				log_err("fio: realloc OOM\n");
				assert(0);
			}
			td->file_locks[cur_files] = FILE_LOCK_NONE;
		}
		td->files_size = new_size;
	}
	td->files[cur_files] = f;
	f->fileno = cur_files;

	/*
	 * init function, io engine may not be loaded yet
	 */
	if (td->io_ops && (td->io_ops->flags & FIO_DISKLESSIO))
		f->real_file_size = -1ULL;

	f->file_name = smalloc_strdup(file_name);
	if (!f->file_name) {
		log_err("fio: smalloc OOM\n");
		assert(0);
	}

	get_file_type(f);

	switch (td->o.file_lock_mode) {
	case FILE_LOCK_NONE:
		break;
	case FILE_LOCK_READWRITE:
		f->rwlock = fio_rwlock_init();
		break;
	case FILE_LOCK_EXCLUSIVE:
		f->lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);
		break;
	default:
		log_err("fio: unknown lock mode: %d\n", td->o.file_lock_mode);
		assert(0);
	}

	td->files_index++;
	if (f->filetype == FIO_TYPE_FILE)
		td->nr_normal_files++;

	set_already_allocated(file_name);

	if (inc)
		td->o.nr_files++;

	dprint(FD_FILE, "file %p \"%s\" added at %d\n", f, f->file_name,
							cur_files);

	return cur_files;
}

int add_file_exclusive(struct thread_data *td, const char *fname)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		if (!strcmp(f->file_name, fname))
			return i;
	}

	return add_file(td, fname, 0, 1);
}

void get_file(struct fio_file *f)
{
	dprint(FD_FILE, "get file %s, ref=%d\n", f->file_name, f->references);
	assert(fio_file_open(f));
	f->references++;
}

int put_file(struct thread_data *td, struct fio_file *f)
{
	int f_ret = 0, ret = 0;

	dprint(FD_FILE, "put file %s, ref=%d\n", f->file_name, f->references);

	if (!fio_file_open(f)) {
		assert(f->fd == -1);
		return 0;
	}

	assert(f->references);
	if (--f->references)
		return 0;

	if (should_fsync(td) && td->o.fsync_on_close) {
		f_ret = fsync(f->fd);
		if (f_ret < 0)
			f_ret = errno;
	}

	if (td->io_ops->close_file)
		ret = td->io_ops->close_file(td, f);

	if (!ret)
		ret = f_ret;

	td->nr_open_files--;
	fio_file_clear_open(f);
	assert(f->fd == -1);
	return ret;
}

void lock_file(struct thread_data *td, struct fio_file *f, enum fio_ddir ddir)
{
	if (!f->lock || td->o.file_lock_mode == FILE_LOCK_NONE)
		return;

	if (td->o.file_lock_mode == FILE_LOCK_READWRITE) {
		if (ddir == DDIR_READ)
			fio_rwlock_read(f->rwlock);
		else
			fio_rwlock_write(f->rwlock);
	} else if (td->o.file_lock_mode == FILE_LOCK_EXCLUSIVE)
		fio_mutex_down(f->lock);

	td->file_locks[f->fileno] = td->o.file_lock_mode;
}

void unlock_file(struct thread_data *td, struct fio_file *f)
{
	if (!f->lock || td->o.file_lock_mode == FILE_LOCK_NONE)
		return;

	if (td->o.file_lock_mode == FILE_LOCK_READWRITE)
		fio_rwlock_unlock(f->rwlock);
	else if (td->o.file_lock_mode == FILE_LOCK_EXCLUSIVE)
		fio_mutex_up(f->lock);

	td->file_locks[f->fileno] = FILE_LOCK_NONE;
}

void unlock_file_all(struct thread_data *td, struct fio_file *f)
{
	if (td->o.file_lock_mode == FILE_LOCK_NONE || !td->file_locks)
		return;
	if (td->file_locks[f->fileno] != FILE_LOCK_NONE)
		unlock_file(td, f);
}

static int recurse_dir(struct thread_data *td, const char *dirname)
{
	struct dirent *dir;
	int ret = 0;
	DIR *D;

	D = opendir(dirname);
	if (!D) {
		char buf[FIO_VERROR_SIZE];

		snprintf(buf, FIO_VERROR_SIZE, "opendir(%s)", dirname);
		td_verror(td, errno, buf);
		return 1;
	}

	while ((dir = readdir(D)) != NULL) {
		char full_path[PATH_MAX];
		struct stat sb;

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		sprintf(full_path, "%s%s%s", dirname, FIO_OS_PATH_SEPARATOR, dir->d_name);

		if (lstat(full_path, &sb) == -1) {
			if (errno != ENOENT) {
				td_verror(td, errno, "stat");
				ret = 1;
				break;
			}
		}

		if (S_ISREG(sb.st_mode)) {
			add_file(td, full_path, 0, 1);
			continue;
		}
		if (!S_ISDIR(sb.st_mode))
			continue;

		ret = recurse_dir(td, full_path);
		if (ret)
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

	dprint(FD_FILE, "dup files: %d\n", org->files_index);

	if (!org->files)
		return;

	td->files = malloc(org->files_index * sizeof(f));

	if (td->o.file_lock_mode != FILE_LOCK_NONE)
		td->file_locks = malloc(org->files_index);

	for_each_file(org, f, i) {
		struct fio_file *__f;

		__f = alloc_new_file(td);

		if (f->file_name) {
			__f->file_name = smalloc_strdup(f->file_name);
			if (!__f->file_name) {
				log_err("fio: smalloc OOM\n");
				assert(0);
			}

			__f->filetype = f->filetype;
		}

		if (td->o.file_lock_mode == FILE_LOCK_EXCLUSIVE)
			__f->lock = f->lock;
		else if (td->o.file_lock_mode == FILE_LOCK_READWRITE)
			__f->rwlock = f->rwlock;

		td->files[i] = __f;
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
	td->o.nr_files = 0;
	td->o.open_files = 0;
	td->files_index = 0;
	td->nr_normal_files = 0;
}

void fio_file_reset(struct thread_data *td, struct fio_file *f)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		f->last_pos[i] = f->file_offset;
		f->last_start[i] = -1ULL;
	}

	if (fio_file_axmap(f))
		axmap_reset(f->io_axmap);
	else if (fio_file_lfsr(f))
		lfsr_reset(&f->lfsr, td->rand_seeds[FIO_RAND_BLOCK_OFF]);
}

int fio_files_done(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i)
		if (!fio_file_done(f))
			return 0;

	return 1;
}

/* free memory used in initialization phase only */
void filesetup_mem_free(void)
{
	free_already_allocated();
}
