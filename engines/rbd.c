/*
 * rbd engine
 *
 * IO engine using Ceph's librbd to test RADOS Block Devices.
 *
 */

#include <rbd/librbd.h>

#include "../fio.h"

struct fio_rbd_iou {
	struct io_u *io_u;
	int io_complete;
};

struct rbd_data {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	struct io_u **aio_events;
};

struct rbd_options {
	struct thread_data *td;
	char *rbd_name;
	char *pool_name;
	char *client_name;
};

static struct fio_option options[] = {
	{
	 .name     = "rbdname",
	 .lname    = "rbd engine rbdname",
	 .type     = FIO_OPT_STR_STORE,
	 .help     = "RBD name for RBD engine",
	 .off1     = offsetof(struct rbd_options, rbd_name),
	 .category = FIO_OPT_C_ENGINE,
	 .group    = FIO_OPT_G_RBD,
	 },
	{
	 .name     = "pool",
	 .lname    = "rbd engine pool",
	 .type     = FIO_OPT_STR_STORE,
	 .help     = "Name of the pool hosting the RBD for the RBD engine",
	 .off1     = offsetof(struct rbd_options, pool_name),
	 .category = FIO_OPT_C_ENGINE,
	 .group    = FIO_OPT_G_RBD,
	 },
	{
	 .name     = "clientname",
	 .lname    = "rbd engine clientname",
	 .type     = FIO_OPT_STR_STORE,
	 .help     = "Name of the ceph client to access the RBD for the RBD engine",
	 .off1     = offsetof(struct rbd_options, client_name),
	 .category = FIO_OPT_C_ENGINE,
	 .group    = FIO_OPT_G_RBD,
	 },
	{
	 .name = NULL,
	 },
};

static int _fio_setup_rbd_data(struct thread_data *td,
			       struct rbd_data **rbd_data_ptr)
{
	struct rbd_data *rbd_data;

	if (td->io_ops->data)
		return 0;

	rbd_data = malloc(sizeof(struct rbd_data));
	if (!rbd_data)
		goto failed;

	memset(rbd_data, 0, sizeof(struct rbd_data));

	rbd_data->aio_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	if (!rbd_data->aio_events)
		goto failed;

	memset(rbd_data->aio_events, 0, td->o.iodepth * sizeof(struct io_u *));

	*rbd_data_ptr = rbd_data;

	return 0;

failed:
	return 1;

}

static int _fio_rbd_connect(struct thread_data *td)
{
	struct rbd_data *rbd_data = td->io_ops->data;
	struct rbd_options *o = td->eo;
	int r;

	r = rados_create(&(rbd_data->cluster), o->client_name);
	if (r < 0) {
		log_err("rados_create failed.\n");
		goto failed_early;
	}

	r = rados_conf_read_file(rbd_data->cluster, NULL);
	if (r < 0) {
		log_err("rados_conf_read_file failed.\n");
		goto failed_early;
	}

	r = rados_connect(rbd_data->cluster);
	if (r < 0) {
		log_err("rados_connect failed.\n");
		goto failed_shutdown;
	}

	r = rados_ioctx_create(rbd_data->cluster, o->pool_name,
			       &(rbd_data->io_ctx));
	if (r < 0) {
		log_err("rados_ioctx_create failed.\n");
		goto failed_shutdown;
	}

	r = rbd_open(rbd_data->io_ctx, o->rbd_name, &(rbd_data->image),
		     NULL /*snap */ );
	if (r < 0) {
		log_err("rbd_open failed.\n");
		goto failed_open;
	}
	return 0;

failed_open:
	rados_ioctx_destroy(rbd_data->io_ctx);
failed_shutdown:
	rados_shutdown(rbd_data->cluster);
failed_early:
	return 1;
}

static void _fio_rbd_disconnect(struct rbd_data *rbd_data)
{
	if (!rbd_data)
		return;

	/* shutdown everything */
	if (rbd_data->image) {
		rbd_close(rbd_data->image);
		rbd_data->image = NULL;
	}

	if (rbd_data->io_ctx) {
		rados_ioctx_destroy(rbd_data->io_ctx);
		rbd_data->io_ctx = NULL;
	}

	if (rbd_data->cluster) {
		rados_shutdown(rbd_data->cluster);
		rbd_data->cluster = NULL;
	}
}

static void _fio_rbd_finish_write_aiocb(rbd_completion_t comp, void *data)
{
	struct io_u *io_u = (struct io_u *)data;
	struct fio_rbd_iou *fio_rbd_iou =
	    (struct fio_rbd_iou *)io_u->engine_data;

	fio_rbd_iou->io_complete = 1;

	/* if write needs to be verified - we should not release comp here
	   without fetching the result */

	rbd_aio_release(comp);
	/* TODO handle error */

	return;
}

static void _fio_rbd_finish_read_aiocb(rbd_completion_t comp, void *data)
{
	struct io_u *io_u = (struct io_u *)data;
	struct fio_rbd_iou *fio_rbd_iou =
	    (struct fio_rbd_iou *)io_u->engine_data;

	fio_rbd_iou->io_complete = 1;

	/* if read needs to be verified - we should not release comp here
	   without fetching the result */
	rbd_aio_release(comp);

	/* TODO handle error */

	return;
}

static struct io_u *fio_rbd_event(struct thread_data *td, int event)
{
	struct rbd_data *rbd_data = td->io_ops->data;

	return rbd_data->aio_events[event];
}

static int fio_rbd_getevents(struct thread_data *td, unsigned int min,
			     unsigned int max, struct timespec *t)
{
	struct rbd_data *rbd_data = td->io_ops->data;
	unsigned int events = 0;
	struct io_u *io_u;
	int i;
	struct fio_rbd_iou *fov;

	do {
		io_u_qiter(&td->io_u_all, io_u, i) {
			if (!(io_u->flags & IO_U_F_FLIGHT))
				continue;

			fov = (struct fio_rbd_iou *)io_u->engine_data;

			if (fov->io_complete) {
				fov->io_complete = 0;
				rbd_data->aio_events[events] = io_u;
				events++;
			}

		}
		if (events < min)
			usleep(100);
		else
			break;

	} while (1);

	return events;
}

static int fio_rbd_queue(struct thread_data *td, struct io_u *io_u)
{
	int r = -1;
	struct rbd_data *rbd_data = td->io_ops->data;
	rbd_completion_t comp;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE) {
		r = rbd_aio_create_completion(io_u,
					      (rbd_callback_t)
					      _fio_rbd_finish_write_aiocb,
					      &comp);
		if (r < 0) {
			log_err
			    ("rbd_aio_create_completion for DDIR_WRITE failed.\n");
			goto failed;
		}

		r = rbd_aio_write(rbd_data->image, io_u->offset,
				  io_u->xfer_buflen, io_u->xfer_buf, comp);
		if (r < 0) {
			log_err("rbd_aio_write failed.\n");
			goto failed;
		}

	} else if (io_u->ddir == DDIR_READ) {
		r = rbd_aio_create_completion(io_u,
					      (rbd_callback_t)
					      _fio_rbd_finish_read_aiocb,
					      &comp);
		if (r < 0) {
			log_err
			    ("rbd_aio_create_completion for DDIR_READ failed.\n");
			goto failed;
		}

		r = rbd_aio_read(rbd_data->image, io_u->offset,
				 io_u->xfer_buflen, io_u->xfer_buf, comp);

		if (r < 0) {
			log_err("rbd_aio_read failed.\n");
			goto failed;
		}

	} else if (io_u->ddir == DDIR_SYNC) {
		r = rbd_flush(rbd_data->image);
		if (r < 0) {
			log_err("rbd_flush failed.\n");
			goto failed;
		}

		return FIO_Q_COMPLETED;
	} else {
		dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
		       io_u->ddir);
		return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;

failed:
	io_u->error = r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static int fio_rbd_init(struct thread_data *td)
{
	int r;

	r = _fio_rbd_connect(td);
	if (r) {
		log_err("fio_rbd_connect failed, return code: %d .\n", r);
		goto failed;
	}

	return 0;

failed:
	return 1;

}

static void fio_rbd_cleanup(struct thread_data *td)
{
	struct rbd_data *rbd_data = td->io_ops->data;

	if (rbd_data) {
		_fio_rbd_disconnect(rbd_data);
		free(rbd_data->aio_events);
		free(rbd_data);
	}

}

static int fio_rbd_setup(struct thread_data *td)
{
	int r = 0;
	rbd_image_info_t info;
	struct fio_file *f;
	struct rbd_data *rbd_data = NULL;
	int major, minor, extra;

	/* log version of librbd. No cluster connection required. */
	rbd_version(&major, &minor, &extra);
	log_info("rbd engine: RBD version: %d.%d.%d\n", major, minor, extra);

	/* allocate engine specific structure to deal with librbd. */
	r = _fio_setup_rbd_data(td, &rbd_data);
	if (r) {
		log_err("fio_setup_rbd_data failed.\n");
		goto cleanup;
	}
	td->io_ops->data = rbd_data;

	/* librbd does not allow us to run first in the main thread and later in a
	 * fork child. It needs to be the same process context all the time. 
	 */
	td->o.use_thread = 1;

	/* connect in the main thread to determine to determine
	 * the size of the given RADOS block device. And disconnect
	 * later on.
	 */
	r = _fio_rbd_connect(td);
	if (r) {
		log_err("fio_rbd_connect failed.\n");
		goto cleanup;
	}

	/* get size of the RADOS block device */
	r = rbd_stat(rbd_data->image, &info, sizeof(info));
	if (r < 0) {
		log_err("rbd_status failed.\n");
		goto disconnect;
	}
	dprint(FD_IO, "rbd-engine: image size: %lu\n", info.size);

	/* taken from "net" engine. Pretend we deal with files,
	 * even if we do not have any ideas about files.
	 * The size of the RBD is set instead of a artificial file.
	 */
	if (!td->files_index) {
		add_file(td, td->o.filename ? : "rbd", 0, 0);
		td->o.nr_files = td->o.nr_files ? : 1;
		td->o.open_files++;
	}
	f = td->files[0];
	f->real_file_size = info.size;

	/* disconnect, then we were only connected to determine
	 * the size of the RBD.
	 */
	_fio_rbd_disconnect(rbd_data);
	return 0;

disconnect:
	_fio_rbd_disconnect(rbd_data);
cleanup:
	fio_rbd_cleanup(td);
	return r;
}

static int fio_rbd_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void fio_rbd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rbd_iou *o = io_u->engine_data;

	if (o) {
		io_u->engine_data = NULL;
		free(o);
	}
}

static int fio_rbd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rbd_iou *o;

	o = malloc(sizeof(*o));
	o->io_complete = 0;
	o->io_u = io_u;
	io_u->engine_data = o;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name               = "rbd",
	.version            = FIO_IOOPS_VERSION,
	.setup              = fio_rbd_setup,
	.init               = fio_rbd_init,
	.queue              = fio_rbd_queue,
	.getevents          = fio_rbd_getevents,
	.event              = fio_rbd_event,
	.cleanup            = fio_rbd_cleanup,
	.open_file          = fio_rbd_open,
	.options            = options,
	.io_u_init          = fio_rbd_io_u_init,
	.io_u_free          = fio_rbd_io_u_free,
	.option_struct_size = sizeof(struct rbd_options),
};

static void fio_init fio_rbd_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_rbd_unregister(void)
{
	unregister_ioengine(&ioengine);
}
