/*
 * glusterfs engine
 *
 * common Glusterfs's gfapi interface
 *
 */

#include "gfapi.h"
#include "../optgroup.h"

struct fio_option gfapi_options[] = {
	{
	 .name = "volume",
	 .lname = "Glusterfs volume",
	 .type = FIO_OPT_STR_STORE,
	 .help = "Name of the Glusterfs volume",
	 .off1 = offsetof(struct gf_options, gf_vol),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_GFAPI,
	 },
	{
	 .name = "brick",
	 .lname = "Glusterfs brick name",
	 .type = FIO_OPT_STR_STORE,
	 .help = "Name of the Glusterfs brick to connect",
	 .off1 = offsetof(struct gf_options, gf_brick),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_GFAPI,
	 },
	{
	 .name = "single-instance",
	 .lname = "Single glusterfs instance",
	 .type = FIO_OPT_BOOL,
	 .help = "Only one glusterfs instance",
	 .off1 = offsetof(struct gf_options, gf_single_instance),
	 .category = FIO_OPT_C_ENGINE,
	 .group = FIO_OPT_G_GFAPI,
	 },
	{
	 .name = NULL,
	 },
};

struct glfs_info {
	struct flist_head	list;
	char			*volume;
	char			*brick;
	glfs_t			*fs;
	int			refcount;
};

static pthread_mutex_t glfs_lock = PTHREAD_MUTEX_INITIALIZER;
static FLIST_HEAD(glfs_list_head);

static glfs_t *fio_gf_new_fs(char *volume, char *brick)
{
	int r = 0;
	glfs_t *fs;
	struct stat sb = { 0, };

	fs = glfs_new(volume);
	if (!fs) {
		log_err("glfs_new failed.\n");
		goto out;
	}
	glfs_set_logging(fs, "/tmp/fio_gfapi.log", 7);
	/* default to tcp */
	r = glfs_set_volfile_server(fs, "tcp", brick, 0);
	if (r) {
		log_err("glfs_set_volfile_server failed.\n");
		goto out;
	}
	r = glfs_init(fs);
	if (r) {
		log_err("glfs_init failed. Is glusterd running on brick?\n");
		goto out;
	}
	sleep(2);
	r = glfs_lstat(fs, ".", &sb);
	if (r) {
		log_err("glfs_lstat failed.\n");
		goto out;
	}

out:
	if (r) {
		glfs_fini(fs);
		fs = NULL;
	}
	return fs;
}

static glfs_t *fio_gf_get_glfs(struct gf_options *opt,
			       char *volume, char *brick)
{
	struct glfs_info *glfs = NULL;
	struct glfs_info *tmp;
	struct flist_head *entry;

	if (!opt->gf_single_instance)
		return fio_gf_new_fs(volume, brick);

	pthread_mutex_lock (&glfs_lock);

	flist_for_each(entry, &glfs_list_head) {
		tmp = flist_entry(entry, struct glfs_info, list);
		if (!strcmp(volume, tmp->volume) &&
		    !strcmp(brick, tmp->brick)) {
			glfs = tmp;
			break;
		}
	}

	if (glfs) {
		glfs->refcount++;
	} else {
		glfs = malloc(sizeof(*glfs));
		if (!glfs)
			goto out;
		INIT_FLIST_HEAD(&glfs->list);
		glfs->refcount = 0;
		glfs->volume = strdup(volume);
		glfs->brick = strdup(brick);
		glfs->fs = fio_gf_new_fs(volume, brick);
		if (!glfs->fs) {
			free(glfs);
			glfs = NULL;
			goto out;
		}

		flist_add_tail(&glfs->list, &glfs_list_head);
		glfs->refcount = 1;
	}

out:
	pthread_mutex_unlock (&glfs_lock);

	if (glfs)
		return glfs->fs;
	return NULL;
}

static void fio_gf_put_glfs(struct gf_options *opt, glfs_t *fs)
{
	struct glfs_info *glfs = NULL;
	struct glfs_info *tmp;
	struct flist_head *entry;

	if (!opt->gf_single_instance) {
		glfs_fini(fs);
		return;
	}

	pthread_mutex_lock (&glfs_lock);

	flist_for_each(entry, &glfs_list_head) {
		tmp = flist_entry(entry, struct glfs_info, list);
		if (tmp->fs == fs) {
			glfs = tmp;
			break;
		}
	}

	if (!glfs) {
		log_err("glfs not found to fini.\n");
	} else {
		glfs->refcount--;

		if (glfs->refcount == 0) {
			glfs_fini(glfs->fs);
			free(glfs->volume);
			free(glfs->brick);
			flist_del(&glfs->list);
		}
	}

	pthread_mutex_unlock (&glfs_lock);
}

int fio_gf_setup(struct thread_data *td)
{
	struct gf_data *g = NULL;
	struct gf_options *opt = td->eo;

	dprint(FD_IO, "fio setup\n");

	if (td->io_ops_data)
		return 0;

	g = malloc(sizeof(struct gf_data));
	if (!g) {
		log_err("malloc failed.\n");
		return -ENOMEM;
	}
	g->fd = NULL;
	g->aio_events = NULL;

	g->fs = fio_gf_get_glfs(opt, opt->gf_vol, opt->gf_brick);
	if (!g->fs)
		goto cleanup;

	dprint(FD_FILE, "fio setup %p\n", g->fs);
	td->io_ops_data = g;
	return 0;
cleanup:
	free(g);
	td->io_ops_data = NULL;
	return -EIO;
}

void fio_gf_cleanup(struct thread_data *td)
{
	struct gf_data *g = td->io_ops_data;

	if (g) {
		if (g->aio_events)
			free(g->aio_events);
		if (g->fd)
			glfs_close(g->fd);
		if (g->fs)
			fio_gf_put_glfs(td->eo, g->fs);
		free(g);
		td->io_ops_data = NULL;
	}
}

int fio_gf_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat buf;
	int ret;
	struct gf_data *g = td->io_ops_data;

	dprint(FD_FILE, "get file size %s\n", f->file_name);

	if (!g || !g->fs) {
		return 0;
	}
	if (fio_file_size_known(f))
		return 0;

	ret = glfs_lstat(g->fs, f->file_name, &buf);
	if (ret < 0) {
		log_err("glfs_lstat failed.\n");
		return ret;
	}

	f->real_file_size = buf.st_size;
	fio_file_set_size_known(f);

	return 0;

}

int fio_gf_open_file(struct thread_data *td, struct fio_file *f)
{

	int flags = 0;
	int ret = 0;
	struct gf_data *g = td->io_ops_data;
	struct stat sb = { 0, };

	if (td_write(td)) {
		if (!read_only)
			flags = O_RDWR;
	} else if (td_read(td)) {
		if (!read_only)
			flags = O_RDWR;
		else
			flags = O_RDONLY;
	}

	if (td->o.odirect)
		flags |= OS_O_DIRECT;
	flags |= td->o.sync_io;

	dprint(FD_FILE, "fio file %s open mode %s td rw %s\n", f->file_name,
	       flags & O_RDONLY ? "ro" : "rw", td_read(td) ? "read" : "write");
	g->fd = glfs_creat(g->fs, f->file_name, flags, 0644);
	if (!g->fd) {
		ret = errno;
		log_err("glfs_creat failed.\n");
		return ret;
	}
	/* file for read doesn't exist or shorter than required, create/extend it */
	if (td_read(td)) {
		if (glfs_lstat(g->fs, f->file_name, &sb)
		    || sb.st_size < f->real_file_size) {
			dprint(FD_FILE, "fio extend file %s from %jd to %" PRIu64 "\n",
			       f->file_name, (intmax_t) sb.st_size, f->real_file_size);
#if defined(CONFIG_GF_NEW_API)
			ret = glfs_ftruncate(g->fd, f->real_file_size, NULL, NULL);
#else
			ret = glfs_ftruncate(g->fd, f->real_file_size);
#endif
			if (ret) {
				log_err("failed fio extend file %s to %" PRIu64 "\n",
					f->file_name, f->real_file_size);
			} else {
				unsigned long long left;
				unsigned int bs;
				char *b;
				int r;

				/* fill the file, copied from extend_file */
				b = malloc(td->o.max_bs[DDIR_WRITE]);

				left = f->real_file_size;
				while (left && !td->terminate) {
					bs = td->o.max_bs[DDIR_WRITE];
					if (bs > left)
						bs = left;

					fill_io_buffer(td, b, bs, bs);

					r = glfs_write(g->fd, b, bs, 0);
					dprint(FD_IO,
					       "fio write %d of %" PRIu64 " file %s\n",
					       r, f->real_file_size,
					       f->file_name);

					if (r > 0) {
						left -= r;
						continue;
					} else {
						if (r < 0) {
							int __e = errno;

							if (__e == ENOSPC) {
								if (td->o.
								    fill_device)
									break;
								log_info
								    ("fio: ENOSPC on laying out "
								     "file, stopping\n");
								break;
							}
							td_verror(td, errno,
								  "write");
						} else
							td_verror(td, EIO,
								  "write");

						break;
					}
				}

				if (b)
					free(b);
				glfs_lseek(g->fd, 0, SEEK_SET);

				if (td->terminate && td->o.unlink) {
					dprint(FD_FILE, "terminate unlink %s\n",
					       f->file_name);
					glfs_unlink(g->fs, f->file_name);
				} else if (td->o.create_fsync) {
#if defined(CONFIG_GF_NEW_API)
					if (glfs_fsync(g->fd, NULL, NULL) < 0) {
#else
					if (glfs_fsync(g->fd) < 0) {
#endif
						dprint(FD_FILE,
						       "failed to sync, close %s\n",
						       f->file_name);
						td_verror(td, errno, "fsync");
						glfs_close(g->fd);
						g->fd = NULL;
						return 1;
					}
				}
			}
		}
	}
#if defined(GFAPI_USE_FADVISE)
	{
		int r = 0;
		if (td_random(td)) {
			r = glfs_fadvise(g->fd, 0, f->real_file_size,
					 POSIX_FADV_RANDOM);
		} else {
			r = glfs_fadvise(g->fd, 0, f->real_file_size,
					 POSIX_FADV_SEQUENTIAL);
		}
		if (r) {
			dprint(FD_FILE, "fio %p fadvise %s status %d\n", g->fs,
			       f->file_name, r);
		}
	}
#endif
	dprint(FD_FILE, "fio %p created %s\n", g->fs, f->file_name);
	f->fd = -1;
	f->shadow_fd = -1;
	td->o.open_files ++;
	return ret;
}

int fio_gf_close_file(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;
	struct gf_data *g = td->io_ops_data;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (g) {
		if (g->fd && glfs_close(g->fd) < 0)
			ret = errno;
		g->fd = NULL;
	}

	return ret;
}

int fio_gf_unlink_file(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;
	struct gf_data *g = td->io_ops_data;

	dprint(FD_FILE, "fd unlink %s\n", f->file_name);

	if (g) {
		if (g->fd && glfs_close(g->fd) < 0)
			ret = errno;

		glfs_unlink(g->fs, f->file_name);

		if (g->fs)
			glfs_fini(g->fs);

		g->fd = NULL;
		free(g);
	}
	td->io_ops_data = NULL;

	return ret;
}
