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
	 .name = NULL,
	 },
};

int fio_gf_setup(struct thread_data *td)
{
	int r = 0;
	struct gf_data *g = NULL;
	struct gf_options *opt = td->eo;
	struct stat sb = { 0, };

	dprint(FD_IO, "fio setup\n");

	if (td->io_ops_data)
		return 0;

	g = malloc(sizeof(struct gf_data));
	if (!g) {
		log_err("malloc failed.\n");
		return -ENOMEM;
	}
	g->fs = NULL;
	g->fd = NULL;
	g->aio_events = NULL;

	g->fs = glfs_new(opt->gf_vol);
	if (!g->fs) {
		log_err("glfs_new failed.\n");
		goto cleanup;
	}
	glfs_set_logging(g->fs, "/tmp/fio_gfapi.log", 7);
	/* default to tcp */
	r = glfs_set_volfile_server(g->fs, "tcp", opt->gf_brick, 0);
	if (r) {
		log_err("glfs_set_volfile_server failed.\n");
		goto cleanup;
	}
	r = glfs_init(g->fs);
	if (r) {
		log_err("glfs_init failed. Is glusterd running on brick?\n");
		goto cleanup;
	}
	sleep(2);
	r = glfs_lstat(g->fs, ".", &sb);
	if (r) {
		log_err("glfs_lstat failed.\n");
		goto cleanup;
	}
	dprint(FD_FILE, "fio setup %p\n", g->fs);
	td->io_ops_data = g;
	return 0;
cleanup:
	if (g->fs)
		glfs_fini(g->fs);
	free(g);
	td->io_ops_data = NULL;
	return r;
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
			glfs_fini(g->fs);
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
	if (td->o.sync_io)
		flags |= O_SYNC;

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
			dprint(FD_FILE, "fio extend file %s from %ld to %ld\n",
			       f->file_name, sb.st_size, f->real_file_size);
			ret = glfs_ftruncate(g->fd, f->real_file_size);
			if (ret) {
				log_err("failed fio extend file %s to %ld\n",
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
					       "fio write %d of %ld file %s\n",
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
					if (glfs_fsync(g->fd) < 0) {
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
