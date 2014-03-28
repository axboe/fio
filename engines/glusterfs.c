/*
 * glusterfs engine
 *
 * IO engine using Glusterfs's gfapi interface
 *
 */

#include <glusterfs/api/glfs.h>

#include "../fio.h"

struct gf_options {
    struct thread_data *td;
    char *gf_vol;
    char *gf_brick;
};

struct gf_data {
    glfs_t *fs;
    glfs_fd_t *fd;
};
static struct fio_option options[] = {
    {
	.name     = "volume",
	.lname    = "Glusterfs volume",
	.type     = FIO_OPT_STR_STORE,
	.help     = "Name of the Glusterfs volume",
	.off1     = offsetof(struct gf_options, gf_vol),
	.category = FIO_OPT_C_ENGINE,
	.group    = FIO_OPT_G_GFAPI,
    },
    {
	.name     = "brick",
	.lname    = "Glusterfs brick name",
	.type     = FIO_OPT_STR_STORE,
	.help     = "Name of the Glusterfs brick to connect",
	.off1     = offsetof(struct gf_options, gf_brick),
	.category = FIO_OPT_C_ENGINE,
	.group    = FIO_OPT_G_GFAPI,
    },
    {
	.name = NULL,
    },
};

static int fio_gf_setup(struct thread_data *td)
{
	int r = 0;
	struct gf_data *g = NULL;
	struct gf_options *opt = td->eo;

	if (td->io_ops->data)
	    return 0;

	g = malloc(sizeof(struct gf_data));
	if (!g){
	    log_err("malloc failed.\n");
	    return -ENOMEM;
	}
	g->fs = NULL; g->fd = NULL;

	g->fs = glfs_new (opt->gf_vol);
	if (!g->fs){
	    log_err("glfs_new failed.\n");
	    goto cleanup;
	}

	/* default to tcp */
	r = glfs_set_volfile_server(g->fs, "tcp", opt->gf_brick, 24007);
	if (r){
	    log_err("glfs_set_volfile_server failed.\n");
	    goto cleanup;
	}
	r = glfs_init(g->fs);
	if (r){
	    log_err("glfs_init failed.\n");
	    goto cleanup;
	}
	glfs_set_logging (g->fs, "/dev/stderr", 7);
	
	td->io_ops->data = g;
cleanup:
	if (g){
	    if (g->fs){
		glfs_fini(g->fs);
	    }
	    free(g);
	}
	return r;
}

static void fio_gf_cleanup(struct thread_data *td)
{
	struct gf_data *g = td->io_ops->data;

	if (g){
	    if (g->fs){
		glfs_fini(g->fs);
	    }
	    free(g);
	}
}

static int fio_gf_get_file_size(struct thread_data *td, struct fio_file *f)
{
    struct stat buf;
    int ret;
    struct gf_data *g = td->io_ops->data;

<<<<<<< HEAD
    dprint(FD_FILE, "get file size %s\n", f->file_name);

    if (!g || !g->fs)
    {
	return 0;
    }
=======
>>>>>>> parent of 6aa5650... make glfs call per thread based
    if (fio_file_size_known(f))
	return 0;

    ret = glfs_lstat (g->fs, f->file_name, &buf);
    if (ret < 0)
	return ret;

    f->real_file_size = buf.st_size;
    fio_file_set_size_known(f);

    return 0;

}

static int fio_gf_open_file(struct thread_data *td, struct fio_file *f)
{
    struct gf_data *g = td->io_ops->data;
    int flags = 0;

    dprint(FD_FILE, "fd open %s\n", f->file_name);

    if (td_write(td)) {
	if (!read_only)
	    flags = O_RDWR;
    } else if (td_read(td)) {
	if (!read_only)
	    flags = O_RDWR;
	else
	    flags = O_RDONLY;
    }
    if (td->o.create_on_open)
	flags |= O_CREAT;

    g->fd = glfs_open(g->fs, f->file_name, flags);
    f->fd = -1;
    return 0;
}

static int fio_gf_close_file(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;
	struct gf_data *g = td->io_ops->data;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (!g->fd && glfs_close(g->fd) < 0)
		ret = errno;

	g->fd = NULL;
	f->engine_data = 0;

	return ret;
}

#define LAST_POS(f)	((f)->engine_data)
static int fio_gf_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct gf_data *g = td->io_ops->data;

	if (!ddir_rw(io_u->ddir))
		return 0;

	if (LAST_POS(f) != -1ULL && LAST_POS(f) == io_u->offset)
		return 0;

	if (glfs_lseek(g->fd, io_u->offset, SEEK_SET) < 0) {
		td_verror(td, errno, "lseek");
		return 1;
	}

	return 0;
}

static int fio_gf_queue(struct thread_data *td, struct io_u *io_u)
{
    struct gf_data *g = td->io_ops->data;
    int ret = 0;

    fio_ro_check(td, io_u);

    if (io_u->ddir == DDIR_READ)
	ret = glfs_read(g->fd, io_u->xfer_buf, io_u->xfer_buflen, 0);
    else if (io_u->ddir == DDIR_WRITE)
	ret = glfs_write(g->fd, io_u->xfer_buf, io_u->xfer_buflen, 0);
    else { 	    
	log_err("unsupported operation.\n");
	return -EINVAL;
    }
    if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
	LAST_POS(io_u->file) = io_u->offset + ret;

    if (ret != (int) io_u->xfer_buflen) {
	if (ret >= 0) {
	    io_u->resid = io_u->xfer_buflen - ret;
	    io_u->error = 0;
	    return FIO_Q_COMPLETED;
	} else
	    io_u->error = errno;
    }

    if (io_u->error)
	td_verror(td, io_u->error, "xfer");

    return FIO_Q_COMPLETED;

}

static struct ioengine_ops ioengine = {
	.name		    = "gfapi",
	.version	    = FIO_IOOPS_VERSION,
	.setup              = fio_gf_setup,
	.cleanup            = fio_gf_cleanup,
	.prep		    = fio_gf_prep,
	.queue		    = fio_gf_queue,
	.open_file	    = fio_gf_open_file,
	.close_file	    = fio_gf_close_file,
	.get_file_size	    = fio_gf_get_file_size,
	.options            = options,
	.option_struct_size = sizeof(struct gf_options),
	.flags		    = FIO_SYNCIO,
};

static void fio_init fio_gf_register(void)
{
    register_ioengine(&ioengine);
}

static void fio_exit fio_gf_unregister(void)
{
    unregister_ioengine(&ioengine);
}
