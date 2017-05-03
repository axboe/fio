/*
 * rbd engine
 *
 * IO engine using Ceph's librbd to test RADOS Block Devices.
 *
 */

#include <rbd/librbd.h>

#include "../fio.h"
#include "../optgroup.h"
#ifdef CONFIG_RBD_BLKIN
#include <zipkin_c.h>
#endif

#ifdef CONFIG_RBD_POLL
/* add for poll */
#include <poll.h>
#include <sys/eventfd.h>
#endif

struct fio_rbd_iou {
	struct io_u *io_u;
	rbd_completion_t completion;
	int io_seen;
	int io_complete;
#ifdef CONFIG_RBD_BLKIN
	struct blkin_trace_info info;
#endif
};

struct rbd_data {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	rbd_image_t image;
	struct io_u **aio_events;
	struct io_u **sort_events;
	int fd; /* add for poll */
	bool connected;
};

struct rbd_options {
	void *pad;
	char *cluster_name;
	char *rbd_name;
	char *pool_name;
	char *client_name;
	int busy_poll;
};

static struct fio_option options[] = {
        {
		.name		= "clustername",
		.lname		= "ceph cluster name",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Cluster name for ceph",
		.off1		= offsetof(struct rbd_options, cluster_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_RBD,
        },
	{
		.name		= "rbdname",
		.lname		= "rbd engine rbdname",
		.type		= FIO_OPT_STR_STORE,
		.help		= "RBD name for RBD engine",
		.off1		= offsetof(struct rbd_options, rbd_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_RBD,
	},
	{
		.name		= "pool",
		.lname		= "rbd engine pool",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of the pool hosting the RBD for the RBD engine",
		.off1		= offsetof(struct rbd_options, pool_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_RBD,
	},
	{
		.name		= "clientname",
		.lname		= "rbd engine clientname",
		.type		= FIO_OPT_STR_STORE,
		.help		= "Name of the ceph client to access the RBD for the RBD engine",
		.off1		= offsetof(struct rbd_options, client_name),
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_RBD,
	},
	{
		.name		= "busy_poll",
		.lname		= "Busy poll",
		.type		= FIO_OPT_BOOL,
		.help		= "Busy poll for completions instead of sleeping",
		.off1		= offsetof(struct rbd_options, busy_poll),
		.def		= "0",
		.category	= FIO_OPT_C_ENGINE,
		.group		= FIO_OPT_G_RBD,
	},
	{
		.name = NULL,
	},
};

static int _fio_setup_rbd_data(struct thread_data *td,
			       struct rbd_data **rbd_data_ptr)
{
	struct rbd_data *rbd;

	if (td->io_ops_data)
		return 0;

	rbd = calloc(1, sizeof(struct rbd_data));
	if (!rbd)
		goto failed;

	rbd->connected = false;

	/* add for poll, init fd: -1 */
	rbd->fd = -1;

	rbd->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!rbd->aio_events)
		goto failed;

	rbd->sort_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!rbd->sort_events)
		goto failed;

	*rbd_data_ptr = rbd;
	return 0;

failed:
	if (rbd) {
		if (rbd->aio_events) 
			free(rbd->aio_events);
		if (rbd->sort_events)
			free(rbd->sort_events);
		free(rbd);
	}
	return 1;

}

#ifdef CONFIG_RBD_POLL
static bool _fio_rbd_setup_poll(struct rbd_data *rbd)
{
	int r;

	/* add for rbd poll */
	rbd->fd = eventfd(0, EFD_NONBLOCK);
	if (rbd->fd < 0) {
		log_err("eventfd failed.\n");
		return false;
	}

	r = rbd_set_image_notification(rbd->image, rbd->fd, EVENT_TYPE_EVENTFD);
	if (r < 0) {
		log_err("rbd_set_image_notification failed.\n");
		close(rbd->fd);
		rbd->fd = -1;
		return false;
	}

	return true;
}
#else
static bool _fio_rbd_setup_poll(struct rbd_data *rbd)
{
	return true;
}
#endif

static int _fio_rbd_connect(struct thread_data *td)
{
	struct rbd_data *rbd = td->io_ops_data;
	struct rbd_options *o = td->eo;
	int r;

	if (o->cluster_name) {
		char *client_name = NULL; 

		/*
		 * If we specify cluser name, the rados_create2
		 * will not assume 'client.'. name is considered
		 * as a full type.id namestr
		 */
		if (o->client_name) {
			if (!index(o->client_name, '.')) {
				client_name = calloc(1, strlen("client.") +
						    strlen(o->client_name) + 1);
				strcat(client_name, "client.");
				strcat(client_name, o->client_name);
			} else {
				client_name = o->client_name;
			}
		}

		r = rados_create2(&rbd->cluster, o->cluster_name,
				 client_name, 0);

		if (client_name && !index(o->client_name, '.'))
			free(client_name);
	} else
		r = rados_create(&rbd->cluster, o->client_name);
	
	if (r < 0) {
		log_err("rados_create failed.\n");
		goto failed_early;
	}

	r = rados_conf_read_file(rbd->cluster, NULL);
	if (r < 0) {
		log_err("rados_conf_read_file failed.\n");
		goto failed_early;
	}

	r = rados_connect(rbd->cluster);
	if (r < 0) {
		log_err("rados_connect failed.\n");
		goto failed_shutdown;
	}

	r = rados_ioctx_create(rbd->cluster, o->pool_name, &rbd->io_ctx);
	if (r < 0) {
		log_err("rados_ioctx_create failed.\n");
		goto failed_shutdown;
	}

	r = rbd_open(rbd->io_ctx, o->rbd_name, &rbd->image, NULL /*snap */ );
	if (r < 0) {
		log_err("rbd_open failed.\n");
		goto failed_open;
	}

	if (!_fio_rbd_setup_poll(rbd))
		goto failed_poll;

	return 0;

failed_poll:
	rbd_close(rbd->image);
	rbd->image = NULL;
failed_open:
	rados_ioctx_destroy(rbd->io_ctx);
	rbd->io_ctx = NULL;
failed_shutdown:
	rados_shutdown(rbd->cluster);
	rbd->cluster = NULL;
failed_early:
	return 1;
}

static void _fio_rbd_disconnect(struct rbd_data *rbd)
{
	if (!rbd)
		return;

	/* close eventfd */
	if (rbd->fd != -1) {
		close(rbd->fd);
		rbd->fd = -1;
	}

	/* shutdown everything */
	if (rbd->image) {
		rbd_close(rbd->image);
		rbd->image = NULL;
	}

	if (rbd->io_ctx) {
		rados_ioctx_destroy(rbd->io_ctx);
		rbd->io_ctx = NULL;
	}

	if (rbd->cluster) {
		rados_shutdown(rbd->cluster);
		rbd->cluster = NULL;
	}
}

static void _fio_rbd_finish_aiocb(rbd_completion_t comp, void *data)
{
	struct fio_rbd_iou *fri = data;
	struct io_u *io_u = fri->io_u;
	ssize_t ret;

	/*
	 * Looks like return value is 0 for success, or < 0 for
	 * a specific error. So we have to assume that it can't do
	 * partial completions.
	 */
	ret = rbd_aio_get_return_value(fri->completion);
	if (ret < 0) {
		io_u->error = -ret;
		io_u->resid = io_u->xfer_buflen;
	} else
		io_u->error = 0;

	fri->io_complete = 1;
}

static struct io_u *fio_rbd_event(struct thread_data *td, int event)
{
	struct rbd_data *rbd = td->io_ops_data;

	return rbd->aio_events[event];
}

static inline int fri_check_complete(struct rbd_data *rbd, struct io_u *io_u,
				     unsigned int *events)
{
	struct fio_rbd_iou *fri = io_u->engine_data;

	if (fri->io_complete) {
		fri->io_seen = 1;
		rbd->aio_events[*events] = io_u;
		(*events)++;

		rbd_aio_release(fri->completion);
		return 1;
	}

	return 0;
}

static inline int rbd_io_u_seen(struct io_u *io_u)
{
	struct fio_rbd_iou *fri = io_u->engine_data;

	return fri->io_seen;
}

static void rbd_io_u_wait_complete(struct io_u *io_u)
{
	struct fio_rbd_iou *fri = io_u->engine_data;

	rbd_aio_wait_for_complete(fri->completion);
}

static int rbd_io_u_cmp(const void *p1, const void *p2)
{
	const struct io_u **a = (const struct io_u **) p1;
	const struct io_u **b = (const struct io_u **) p2;
	uint64_t at, bt;

	at = utime_since_now(&(*a)->start_time);
	bt = utime_since_now(&(*b)->start_time);

	if (at < bt)
		return -1;
	else if (at == bt)
		return 0;
	else
		return 1;
}

static int rbd_iter_events(struct thread_data *td, unsigned int *events,
			   unsigned int min_evts, int wait)
{
	struct rbd_data *rbd = td->io_ops_data;
	unsigned int this_events = 0;
	struct io_u *io_u;
	int i, sidx = 0;

#ifdef CONFIG_RBD_POLL
	int ret = 0;
	int event_num = 0;
	struct fio_rbd_iou *fri = NULL;
	rbd_completion_t comps[min_evts];

	struct pollfd pfd;
	pfd.fd = rbd->fd;
	pfd.events = POLLIN;

	ret = poll(&pfd, 1, -1);
	if (ret <= 0)
		return 0;

	assert(pfd.revents & POLLIN);

	event_num = rbd_poll_io_events(rbd->image, comps, min_evts);

	for (i = 0; i < event_num; i++) {
		fri = rbd_aio_get_arg(comps[i]);
		io_u = fri->io_u;
#else
	io_u_qiter(&td->io_u_all, io_u, i) {
#endif
		if (!(io_u->flags & IO_U_F_FLIGHT))
			continue;
		if (rbd_io_u_seen(io_u))
			continue;

		if (fri_check_complete(rbd, io_u, events))
			this_events++;
		else if (wait)
			rbd->sort_events[sidx++] = io_u;
	}

	if (!wait || !sidx)
		return this_events;

	/*
	 * Sort events, oldest issue first, then wait on as many as we
	 * need in order of age. If we have enough events, stop waiting,
	 * and just check if any of the older ones are done.
	 */
	if (sidx > 1)
		qsort(rbd->sort_events, sidx, sizeof(struct io_u *), rbd_io_u_cmp);

	for (i = 0; i < sidx; i++) {
		io_u = rbd->sort_events[i];

		if (fri_check_complete(rbd, io_u, events)) {
			this_events++;
			continue;
		}

		/*
		 * Stop waiting when we have enough, but continue checking
		 * all pending IOs if they are complete.
		 */
		if (*events >= min_evts)
			continue;

		rbd_io_u_wait_complete(io_u);

		if (fri_check_complete(rbd, io_u, events))
			this_events++;
	}

	return this_events;
}

static int fio_rbd_getevents(struct thread_data *td, unsigned int min,
			     unsigned int max, const struct timespec *t)
{
	unsigned int this_events, events = 0;
	struct rbd_options *o = td->eo;
	int wait = 0;

	do {
		this_events = rbd_iter_events(td, &events, min, wait);

		if (events >= min)
			break;
		if (this_events)
			continue;

		if (!o->busy_poll)
			wait = 1;
		else
			nop;
	} while (1);

	return events;
}

static int fio_rbd_queue(struct thread_data *td, struct io_u *io_u)
{
	struct rbd_data *rbd = td->io_ops_data;
	struct fio_rbd_iou *fri = io_u->engine_data;
	int r = -1;

	fio_ro_check(td, io_u);

	fri->io_seen = 0;
	fri->io_complete = 0;

	r = rbd_aio_create_completion(fri, _fio_rbd_finish_aiocb,
						&fri->completion);
	if (r < 0) {
		log_err("rbd_aio_create_completion failed.\n");
		goto failed;
	}

	if (io_u->ddir == DDIR_WRITE) {
#ifdef CONFIG_RBD_BLKIN
		blkin_init_trace_info(&fri->info);
		r = rbd_aio_write_traced(rbd->image, io_u->offset, io_u->xfer_buflen,
					 io_u->xfer_buf, fri->completion, &fri->info);
#else
		r = rbd_aio_write(rbd->image, io_u->offset, io_u->xfer_buflen,
					 io_u->xfer_buf, fri->completion);
#endif
		if (r < 0) {
			log_err("rbd_aio_write failed.\n");
			goto failed_comp;
		}

	} else if (io_u->ddir == DDIR_READ) {
#ifdef CONFIG_RBD_BLKIN
		blkin_init_trace_info(&fri->info);
		r = rbd_aio_read_traced(rbd->image, io_u->offset, io_u->xfer_buflen,
					io_u->xfer_buf, fri->completion, &fri->info);
#else
		r = rbd_aio_read(rbd->image, io_u->offset, io_u->xfer_buflen,
					io_u->xfer_buf, fri->completion);
#endif

		if (r < 0) {
			log_err("rbd_aio_read failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_TRIM) {
		r = rbd_aio_discard(rbd->image, io_u->offset,
					io_u->xfer_buflen, fri->completion);
		if (r < 0) {
			log_err("rbd_aio_discard failed.\n");
			goto failed_comp;
		}
	} else if (io_u->ddir == DDIR_SYNC) {
		r = rbd_aio_flush(rbd->image, fri->completion);
		if (r < 0) {
			log_err("rbd_flush failed.\n");
			goto failed_comp;
		}
	} else {
		dprint(FD_IO, "%s: Warning: unhandled ddir: %d\n", __func__,
		       io_u->ddir);
		goto failed_comp;
	}

	return FIO_Q_QUEUED;
failed_comp:
	rbd_aio_release(fri->completion);
failed:
	io_u->error = -r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static int fio_rbd_init(struct thread_data *td)
{
	int r;
	struct rbd_data *rbd = td->io_ops_data;

	if (rbd->connected)
		return 0;

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
	struct rbd_data *rbd = td->io_ops_data;

	if (rbd) {
		_fio_rbd_disconnect(rbd);
		free(rbd->aio_events);
		free(rbd->sort_events);
		free(rbd);
	}
}

static int fio_rbd_setup(struct thread_data *td)
{
	rbd_image_info_t info;
	struct fio_file *f;
	struct rbd_data *rbd = NULL;
	int r;

	/* allocate engine specific structure to deal with librbd. */
	r = _fio_setup_rbd_data(td, &rbd);
	if (r) {
		log_err("fio_setup_rbd_data failed.\n");
		goto cleanup;
	}
	td->io_ops_data = rbd;

	/* librbd does not allow us to run first in the main thread and later
	 * in a fork child. It needs to be the same process context all the
	 * time. 
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
	rbd->connected = true;

	/* get size of the RADOS block device */
	r = rbd_stat(rbd->image, &info, sizeof(info));
	if (r < 0) {
		log_err("rbd_status failed.\n");
		goto cleanup;
	} else if (info.size == 0) {
		log_err("image size should be larger than zero.\n");
		r = -EINVAL;
		goto cleanup;
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

	return 0;

cleanup:
	fio_rbd_cleanup(td);
	return r;
}

static int fio_rbd_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int fio_rbd_invalidate(struct thread_data *td, struct fio_file *f)
{
#if defined(CONFIG_RBD_INVAL)
	struct rbd_data *rbd = td->io_ops_data;

	return rbd_invalidate_cache(rbd->image);
#else
	return 0;
#endif
}

static void fio_rbd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rbd_iou *fri = io_u->engine_data;

	if (fri) {
		io_u->engine_data = NULL;
		free(fri);
	}
}

static int fio_rbd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rbd_iou *fri;

	fri = calloc(1, sizeof(*fri));
	fri->io_u = io_u;
	io_u->engine_data = fri;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "rbd",
	.version		= FIO_IOOPS_VERSION,
	.setup			= fio_rbd_setup,
	.init			= fio_rbd_init,
	.queue			= fio_rbd_queue,
	.getevents		= fio_rbd_getevents,
	.event			= fio_rbd_event,
	.cleanup		= fio_rbd_cleanup,
	.open_file		= fio_rbd_open,
	.invalidate		= fio_rbd_invalidate,
	.options		= options,
	.io_u_init		= fio_rbd_io_u_init,
	.io_u_free		= fio_rbd_io_u_free,
	.option_struct_size	= sizeof(struct rbd_options),
};

static void fio_init fio_rbd_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_rbd_unregister(void)
{
	unregister_ioengine(&ioengine);
}
