/*
 * glusterfs engine
 *
 * IO engine using Glusterfs's gfapi async interface
 *
 */
#include "gfapi.h"
#define NOT_YET 1
struct fio_gf_iou {
	struct io_u *io_u;
	int io_complete;
};

static struct io_u *fio_gf_event(struct thread_data *td, int event)
{
	struct gf_data *gf_data = td->io_ops_data;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	return gf_data->aio_events[event];
}

static int fio_gf_getevents(struct thread_data *td, unsigned int min,
			    unsigned int max, const struct timespec *t)
{
	struct gf_data *g = td->io_ops_data;
	unsigned int events = 0;
	struct io_u *io_u;
	int i;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	do {
		io_u_qiter(&td->io_u_all, io_u, i) {
			struct fio_gf_iou *io;

			if (!(io_u->flags & IO_U_F_FLIGHT))
				continue;

			io = io_u->engine_data;
			if (io->io_complete) {
				io->io_complete = 0;
				g->aio_events[events] = io_u;
				events++;

				if (events >= max)
					break;
			}

		}
		if (events < min)
			usleep(100);
		else
			break;

	} while (1);

	return events;
}

static void fio_gf_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_gf_iou *io = io_u->engine_data;

	if (io) {
		if (io->io_complete)
			log_err("incomplete IO found.\n");
		io_u->engine_data = NULL;
		free(io);
	}
}

static int fio_gf_io_u_init(struct thread_data *td, struct io_u *io_u)
{
    struct fio_gf_iou *io;
	dprint(FD_FILE, "%s\n", __FUNCTION__);
    
    io = malloc(sizeof(struct fio_gf_iou));
    if (!io) {
        td_verror(td, errno, "malloc");
        return 1;
    }
    io->io_complete = 0;
    io->io_u = io_u;
    io_u->engine_data = io;
	return 0;
}

#if defined(CONFIG_GF_NEW_API)
static void gf_async_cb(glfs_fd_t * fd, ssize_t ret, struct glfs_stat *prestat,
			struct glfs_stat *poststat, void *data)
#else
static void gf_async_cb(glfs_fd_t * fd, ssize_t ret, void *data)
#endif
{
	struct io_u *io_u = data;
	struct fio_gf_iou *iou = io_u->engine_data;

	dprint(FD_IO, "%s ret %zd\n", __FUNCTION__, ret);
	iou->io_complete = 1;
}

static enum fio_q_status fio_gf_async_queue(struct thread_data fio_unused * td,
					    struct io_u *io_u)
{
	struct gf_data *g = td->io_ops_data;
	int r;

	dprint(FD_IO, "%s op %s\n", __FUNCTION__, io_ddir_name(io_u->ddir));

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		r = glfs_pread_async(g->fd, io_u->xfer_buf, io_u->xfer_buflen,
				     io_u->offset, 0, gf_async_cb, io_u);
	else if (io_u->ddir == DDIR_WRITE)
		r = glfs_pwrite_async(g->fd, io_u->xfer_buf, io_u->xfer_buflen,
				      io_u->offset, 0, gf_async_cb, io_u);
#if defined(CONFIG_GF_TRIM)
	else if (io_u->ddir == DDIR_TRIM)
		r = glfs_discard_async(g->fd, io_u->offset, io_u->xfer_buflen,
				       gf_async_cb, io_u);
#endif
	else if (io_u->ddir == DDIR_DATASYNC)
		r = glfs_fdatasync_async(g->fd, gf_async_cb, io_u);
	else if (io_u->ddir == DDIR_SYNC)
		r = glfs_fsync_async(g->fd, gf_async_cb, io_u);
	else
		r = EINVAL;

	if (r) {
		log_err("glfs queue failed.\n");
		io_u->error = r;
		goto failed;
	}
	return FIO_Q_QUEUED;

failed:
	io_u->error = r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static int fio_gf_async_setup(struct thread_data *td)
{
	struct gf_data *g;
	int r;

#if defined(NOT_YET)
	log_err("the async interface is still very experimental...\n");
#endif
	r = fio_gf_setup(td);
	if (r)
		return r;

	td->o.use_thread = 1;
	g = td->io_ops_data;
	g->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!g->aio_events) {
		r = -ENOMEM;
		fio_gf_cleanup(td);
		return r;
	}

	return r;
}

static struct ioengine_ops ioengine = {
	.name = "gfapi_async",
	.version = FIO_IOOPS_VERSION,
	.init = fio_gf_async_setup,
	.cleanup = fio_gf_cleanup,
	.queue = fio_gf_async_queue,
	.open_file = fio_gf_open_file,
	.close_file = fio_gf_close_file,
	.unlink_file = fio_gf_unlink_file,
	.get_file_size = fio_gf_get_file_size,
	.getevents = fio_gf_getevents,
	.event = fio_gf_event,
	.io_u_init = fio_gf_io_u_init,
	.io_u_free = fio_gf_io_u_free,
	.options = gfapi_options,
	.option_struct_size = sizeof(struct gf_options),
	.flags = FIO_DISKLESSIO,
};

static void fio_init fio_gf_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_gf_unregister(void)
{
	unregister_ioengine(&ioengine);
}
