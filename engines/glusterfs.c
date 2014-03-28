/*
 * glusterfs engine
 *
 * IO engine using Glusterfs's gfapi interface
 *
 */

#include <glusterfs/api/glfs.h>
#include <glusterfs/api/glfs-handles.h>
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
        struct stat sb = {0, };

	dprint(FD_IO, "fio setup\n");

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
	glfs_set_logging (g->fs, "/tmp/fio_gfapi.log", 7);
	/* default to tcp */
	r = glfs_set_volfile_server(g->fs, "tcp", opt->gf_brick, 0);
	if (r){
	    log_err("glfs_set_volfile_server failed.\n");
	    goto cleanup;
	}
	r = glfs_init(g->fs);
	if (r){
	    log_err("glfs_init failed. Is glusterd running on brick?\n");
	    goto cleanup;
	}
	sleep(2);
	r = glfs_lstat (g->fs, ".", &sb);
	if (r){
	    log_err("glfs_lstat failed.\n");
	    goto cleanup;
	}
	dprint(FD_FILE, "fio setup %p\n", g->fs);
	td->io_ops->data = g;
cleanup:
	if (r){
	    if (g){
		if (g->fs){
		    glfs_fini(g->fs);
		}
		free(g);
	    }
	}
	return r;
}

static void fio_gf_cleanup(struct thread_data *td)
{
}

static int fio_gf_get_file_size(struct thread_data *td, struct fio_file *f)
{
    struct stat buf;
    int ret;
    struct gf_data *g = td->io_ops->data;

    dprint(FD_FILE, "get file size %s\n", f->file_name);

    if (!g || !g->fs)
    {
	f->real_file_size = 0;
	fio_file_set_size_known(f);
    }
    if (fio_file_size_known(f))
	return 0;

    ret = glfs_lstat (g->fs, f->file_name, &buf);
    if (ret < 0){
	log_err("glfs_lstat failed.\n");
	return ret;
    }

    f->real_file_size = buf.st_size;
    fio_file_set_size_known(f);

    return 0;

}

static int fio_gf_open_file(struct thread_data *td, struct fio_file *f)
{

    int flags = 0;
    int ret = 0;
    struct gf_data *g = td->io_ops->data;

    dprint(FD_FILE, "fio open %s\n", f->file_name);
    if (td_write(td)) {
	if (!read_only)
	    flags = O_RDWR;
    } else if (td_read(td)) {
	if (!read_only)
	    flags = O_RDWR;
	else
	    flags = O_RDONLY;
    }
    g->fd = glfs_creat(g->fs, f->file_name, flags, 0644);
    if (!g->fd){
	log_err("glfs_creat failed.\n");
	ret = errno;
    }
    dprint(FD_FILE, "fio %p created %s\n", g->fs, f->file_name);
    f->fd = -1;
    f->shadow_fd = -1;    

    return ret;
}

static int fio_gf_close_file(struct thread_data *td, struct fio_file *f)
{
	int ret = 0;
	struct gf_data *g = td->io_ops->data;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (g->fd && glfs_close(g->fd) < 0)
	    ret = errno;

	if (g->fs)
	    glfs_fini(g->fs);

	g->fd = NULL;
	free(g);
	td->io_ops->data = NULL;
	f->engine_data = 0;

	return ret;
}

#define LAST_POS(f)	((f)->engine_data)
static int fio_gf_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct gf_data *g = td->io_ops->data;

	dprint(FD_FILE, "fio prep\n");

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

    dprint(FD_FILE, "fio queue len %lu\n", io_u->xfer_buflen);
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

    if (io_u->error){
	log_err("IO failed.\n");
	td_verror(td, io_u->error, "xfer");
    }

    return FIO_Q_COMPLETED;

}

static struct ioengine_ops ioengine = {
	.name		    = "gfapi",
	.version	    = FIO_IOOPS_VERSION,
	.init               = fio_gf_setup,
	.cleanup            = fio_gf_cleanup,
	.prep		    = fio_gf_prep,
	.queue		    = fio_gf_queue,
	.open_file	    = fio_gf_open_file,
	.close_file	    = fio_gf_close_file,
	.get_file_size	    = fio_gf_get_file_size,
	.options            = options,
	.option_struct_size = sizeof(struct gf_options),
	.flags		    = FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_gf_register(void)
{
    register_ioengine(&ioengine);
}

static void fio_exit fio_gf_unregister(void)
{
    unregister_ioengine(&ioengine);
}
