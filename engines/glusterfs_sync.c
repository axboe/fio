/*
 * glusterfs engine
 *
 * IO engine using Glusterfs's gfapi sync interface
 *
 */

#include "gfapi.h"

#define LAST_POS(f)	((f)->engine_pos)
static int fio_gf_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct gf_data *g = td->io_ops_data;

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

static enum fio_q_status fio_gf_queue(struct thread_data *td, struct io_u *io_u)
{
	struct gf_data *g = td->io_ops_data;
	int ret = 0;

	dprint(FD_FILE, "fio queue len %llu\n", io_u->xfer_buflen);
	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = glfs_read(g->fd, io_u->xfer_buf, io_u->xfer_buflen, 0);
	else if (io_u->ddir == DDIR_WRITE)
		ret = glfs_write(g->fd, io_u->xfer_buf, io_u->xfer_buflen, 0);
	else if (io_u->ddir == DDIR_SYNC)
#if defined(CONFIG_GF_NEW_API)
		ret = glfs_fsync(g->fd, NULL, NULL);
#else
		ret = glfs_fsync(g->fd);
#endif
	else if (io_u->ddir == DDIR_DATASYNC)
#if defined(CONFIG_GF_NEW_API)
		ret = glfs_fdatasync(g->fd, NULL, NULL);
#else
		ret = glfs_fdatasync(g->fd);
#endif
	else {
		log_err("unsupported operation.\n");
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}
	dprint(FD_FILE, "fio len %llu ret %d\n", io_u->xfer_buflen, ret);
	if (io_u->file && ret >= 0 && ddir_rw(io_u->ddir))
		LAST_POS(io_u->file) = io_u->offset + ret;

	if (ret != (int)io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error) {
		log_err("IO failed.\n");
		td_verror(td, io_u->error, "xfer");
	}

	return FIO_Q_COMPLETED;

}

static struct ioengine_ops ioengine = {
	.name = "gfapi",
	.version = FIO_IOOPS_VERSION,
	.init = fio_gf_setup,
	.cleanup = fio_gf_cleanup,
	.prep = fio_gf_prep,
	.queue = fio_gf_queue,
	.open_file = fio_gf_open_file,
	.close_file = fio_gf_close_file,
	.unlink_file = fio_gf_unlink_file,
	.get_file_size = fio_gf_get_file_size,
	.options = gfapi_options,
	.option_struct_size = sizeof(struct gf_options),
	.flags = FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_gf_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_gf_unregister(void)
{
	unregister_ioengine(&ioengine);
}
