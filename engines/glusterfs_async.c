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
static ulong cb_count = 0, issued = 0;

static struct io_u *fio_gf_event(struct thread_data *td, int event)
{
	struct gf_data *gf_data = td->io_ops->data;
	dprint(FD_IO, "%s\n", __FUNCTION__);
	return gf_data->aio_events[event];
}

static int fio_gf_getevents(struct thread_data *td, unsigned int min,
			    unsigned int max, struct timespec *t)
{
	struct gf_data *g = td->io_ops->data;
	unsigned int events = 0;
	struct io_u *io_u;
	int i = 0;
	struct fio_gf_iou *io = NULL;

	dprint(FD_IO, "%s\n", __FUNCTION__);
	do {
		io_u_qiter(&td->io_u_all, io_u, i) {
			if (!(io_u->flags & IO_U_F_FLIGHT))
				continue;

			io = (struct fio_gf_iou *)io_u->engine_data;

			if (io && io->io_complete) {
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
		if (io->io_complete) {
			log_err("incomplete IO found.\n");
		}
		io_u->engine_data = NULL;
		free(io);
	}
	fprintf(stderr, "issued %lu finished %lu\n", issued, cb_count);
}

static int fio_gf_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_gf_iou *io = NULL;

	dprint(FD_FILE, "%s\n", __FUNCTION__);

	if (!io_u->engine_data) {
		io = malloc(sizeof(struct fio_gf_iou));
		if (!io) {
			td_verror(td, errno, "malloc");
			return 1;
		}
		io->io_complete = 0;
		io->io_u = io_u;
		io_u->engine_data = io;
	}
	return 0;
}

static void gf_async_cb(glfs_fd_t * fd, ssize_t ret, void *data)
{
	struct io_u *io_u = (struct io_u *)data;
	struct fio_gf_iou *iou = (struct fio_gf_iou *)io_u->engine_data;

	dprint(FD_IO, "%s ret %lu\n", __FUNCTION__, ret);
	iou->io_complete = 1;
	cb_count++;
}

static int fio_gf_async_queue(struct thread_data fio_unused * td,
			      struct io_u *io_u)
{
	struct gf_data *g = td->io_ops->data;
	int r = 0;

	dprint(FD_IO, "%s op %s\n", __FUNCTION__,
	       io_u->ddir == DDIR_READ ? "read" : io_u->ddir ==
	       DDIR_WRITE ? "write" : io_u->ddir ==
	       DDIR_SYNC ? "sync" : "unknown");

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		r = glfs_pread_async(g->fd, io_u->xfer_buf, io_u->xfer_buflen,
				     io_u->offset, 0, gf_async_cb,
				     (void *)io_u);
	else if (io_u->ddir == DDIR_WRITE)
		r = glfs_pwrite_async(g->fd, io_u->xfer_buf, io_u->xfer_buflen,
				      io_u->offset, 0, gf_async_cb,
				      (void *)io_u);
	else if (io_u->ddir == DDIR_SYNC) {
		r = glfs_fsync_async(g->fd, gf_async_cb, (void *)io_u);
	} else {
		log_err("unsupported operation.\n");
		io_u->error = -EINVAL;
		goto failed;
	}
	if (r) {
		log_err("glfs failed.\n");
		io_u->error = r;
		goto failed;
	}
	issued++;
	return FIO_Q_QUEUED;

failed:
	io_u->error = r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

int fio_gf_async_setup(struct thread_data *td)
{
	int r = 0;
	struct gf_data *g = NULL;
#if defined(NOT_YET)
	fprintf(stderr, "the async interface is still very experimental...\n");
#endif
	r = fio_gf_setup(td);
	if (r) {
		return r;
	}
	td->o.use_thread = 1;
	g = td->io_ops->data;
	g->aio_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	if (!g->aio_events) {
		r = -ENOMEM;
		fio_gf_cleanup(td);
		return r;
	}

	memset(g->aio_events, 0, td->o.iodepth * sizeof(struct io_u *));

	return r;

}

static int fio_gf_async_prep(struct thread_data *td, struct io_u *io_u)
{
	dprint(FD_FILE, "%s\n", __FUNCTION__);

	if (!ddir_rw(io_u->ddir))
		return 0;

	return 0;
}

static struct ioengine_ops ioengine = {
	.name = "gfapi_async",
	.version = FIO_IOOPS_VERSION,
	.init = fio_gf_async_setup,
	.cleanup = fio_gf_cleanup,
	.prep = fio_gf_async_prep,
	.queue = fio_gf_async_queue,
	.open_file = fio_gf_open_file,
	.close_file = fio_gf_close_file,
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
