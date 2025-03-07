/*
 *  Ceph Rados engine
 *
 * IO engine using Ceph's RADOS interface to test low-level performance of
 * Ceph OSDs.
 *
 */

#include <rados/librados.h>
#include <pthread.h>
#include "fio.h"
#include "../optgroup.h"

struct rados_data {
	rados_t cluster;
	rados_ioctx_t io_ctx;
	struct io_u **aio_events;
	bool connected;
	pthread_mutex_t completed_lock;
	pthread_cond_t completed_more_io;
	struct flist_head completed_operations;
	uint64_t ops_scheduled;
	uint64_t ops_completed;
};

struct fio_rados_iou {
	struct flist_head list;
	struct thread_data *td;
	struct io_u *io_u;
	rados_completion_t completion;
	rados_write_op_t write_op;
};

/* fio configuration options read from the job file */
struct rados_options {
	void *pad;
	char *cluster_name;
	char *pool_name;
	char *client_name;
	char *conf;
	int busy_poll;
	int touch_objects;
};

static struct fio_option options[] = {
	{
		.name     = "clustername",
		.lname    = "ceph cluster name",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Cluster name for ceph",
		.off1     = offsetof(struct rados_options, cluster_name),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = "pool",
		.lname    = "pool name to use",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Ceph pool name to benchmark against",
		.off1     = offsetof(struct rados_options, pool_name),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = "clientname",
		.lname    = "rados engine clientname",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Name of the ceph client to access RADOS engine",
		.off1     = offsetof(struct rados_options, client_name),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = "conf",
		.lname    = "ceph configuration file path",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Path of the ceph configuration file",
		.off1     = offsetof(struct rados_options, conf),
		.def      = "/etc/ceph/ceph.conf",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = "busy_poll",
		.lname    = "busy poll mode",
		.type     = FIO_OPT_BOOL,
		.help     = "Busy poll for completions instead of sleeping",
		.off1     = offsetof(struct rados_options, busy_poll),
		.def	  = "0",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = "touch_objects",
		.lname    = "touch objects on start",
		.type     = FIO_OPT_BOOL,
		.help     = "Touch (create) objects on start",
		.off1     = offsetof(struct rados_options, touch_objects),
		.def	  = "1",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_RBD,
	},
	{
		.name     = NULL,
	},
};

static int _fio_setup_rados_data(struct thread_data *td,
				struct rados_data **rados_data_ptr)
{
	struct rados_data *rados;

	if (td->io_ops_data)
		return 0;

	rados = calloc(1, sizeof(struct rados_data));
	if (!rados)
		goto failed;

	rados->connected = false;

	rados->aio_events = calloc(td->o.iodepth, sizeof(struct io_u *));
	if (!rados->aio_events)
		goto failed;
	pthread_mutex_init(&rados->completed_lock, NULL);
	pthread_cond_init(&rados->completed_more_io, NULL);
	INIT_FLIST_HEAD(&rados->completed_operations);
	rados->ops_scheduled = 0;
	rados->ops_completed = 0;
	*rados_data_ptr = rados;
	return 0;

failed:
	if (rados) {
		if (rados->aio_events)
			free(rados->aio_events);
		free(rados);
	}
	return 1;
}

static void _fio_rados_rm_objects(struct thread_data *td, struct rados_data *rados)
{
	size_t i;
	for (i = 0; i < td->o.nr_files; i++) {
		struct fio_file *f = td->files[i];
		rados_remove(rados->io_ctx, f->file_name);
	}
}

static int _fio_rados_connect(struct thread_data *td)
{
	struct rados_data *rados = td->io_ops_data;
	struct rados_options *o = td->eo;
	int r;
	const uint64_t file_size =
		td->o.size / (td->o.nr_files ? td->o.nr_files : 1u);
	struct fio_file *f;
	uint32_t i;

	if (o->cluster_name) {
		char *client_name = NULL;

		/*
		* If we specify cluster name, the rados_create2
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

		r = rados_create2(&rados->cluster, o->cluster_name,
			client_name, 0);

		if (client_name && !index(o->client_name, '.'))
			free(client_name);
	} else
		r = rados_create(&rados->cluster, o->client_name);

	if (o->pool_name == NULL) {
		log_err("rados pool name must be provided.\n");
		goto failed_early;
	}

	if (r < 0) {
		log_err("rados_create failed.\n");
		goto failed_early;
	}

	r = rados_conf_read_file(rados->cluster, o->conf);
	if (r < 0) {
		log_err("rados_conf_read_file failed.\n");
		goto failed_early;
	}

	r = rados_connect(rados->cluster);
	if (r < 0) {
		log_err("rados_connect failed.\n");
		goto failed_early;
	}

	r = rados_ioctx_create(rados->cluster, o->pool_name, &rados->io_ctx);
	if (r < 0) {
		log_err("rados_ioctx_create failed.\n");
		goto failed_shutdown;
	}

	for (i = 0; i < td->o.nr_files; i++) {
		f = td->files[i];
		f->real_file_size = file_size;
		if (o->touch_objects) {
			r = rados_write(rados->io_ctx, f->file_name, "", 0, 0);
			if (r < 0) {
				goto failed_obj_create;
			}
		}
	}
	return 0;

failed_obj_create:
	_fio_rados_rm_objects(td, rados);
	rados_ioctx_destroy(rados->io_ctx);
	rados->io_ctx = NULL;
failed_shutdown:
	rados_shutdown(rados->cluster);
	rados->cluster = NULL;
failed_early:
	return 1;
}

static void _fio_rados_disconnect(struct rados_data *rados)
{
	if (!rados)
		return;

	if (rados->io_ctx) {
		rados_ioctx_destroy(rados->io_ctx);
		rados->io_ctx = NULL;
	}

	if (rados->cluster) {
		rados_shutdown(rados->cluster);
		rados->cluster = NULL;
	}
}

static void fio_rados_cleanup(struct thread_data *td)
{
	struct rados_data *rados = td->io_ops_data;
	if (rados) {
		pthread_mutex_lock(&rados->completed_lock);
		while (rados->ops_scheduled != rados->ops_completed)
			pthread_cond_wait(&rados->completed_more_io, &rados->completed_lock);
		pthread_mutex_unlock(&rados->completed_lock);
		_fio_rados_rm_objects(td, rados);
		_fio_rados_disconnect(rados);
		free(rados->aio_events);
		free(rados);
	}
}

static void complete_callback(rados_completion_t cb, void *arg)
{
	struct fio_rados_iou *fri = (struct fio_rados_iou *)arg;
	struct rados_data *rados = fri->td->io_ops_data;
	assert(fri->completion);
	assert(rados_aio_is_complete(fri->completion));
	pthread_mutex_lock(&rados->completed_lock);
	flist_add_tail(&fri->list, &rados->completed_operations);
	rados->ops_completed++;
	pthread_mutex_unlock(&rados->completed_lock);
	pthread_cond_signal(&rados->completed_more_io);
}

static enum fio_q_status fio_rados_queue(struct thread_data *td,
					 struct io_u *io_u)
{
	struct rados_data *rados = td->io_ops_data;
	struct fio_rados_iou *fri = io_u->engine_data;
	char *object = io_u->file->file_name;
	int r = -1;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE) {
		 r = rados_aio_create_completion(fri, complete_callback,
			NULL, &fri->completion);
		if (r < 0) {
			log_err("rados_aio_create_completion failed.\n");
			goto failed;
		}

		r = rados_aio_write(rados->io_ctx, object, fri->completion,
			io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
		if (r < 0) {
			log_err("rados_write failed.\n");
			goto failed_comp;
		}
		rados->ops_scheduled++;
		return FIO_Q_QUEUED;
	} else if (io_u->ddir == DDIR_READ) {
		r = rados_aio_create_completion(fri, complete_callback,
			NULL, &fri->completion);
		if (r < 0) {
			log_err("rados_aio_create_completion failed.\n");
			goto failed;
		}
		r = rados_aio_read(rados->io_ctx, object, fri->completion,
			io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
		if (r < 0) {
			log_err("rados_aio_read failed.\n");
			goto failed_comp;
		}
		rados->ops_scheduled++;
		return FIO_Q_QUEUED;
	} else if (io_u->ddir == DDIR_TRIM) {
		r = rados_aio_create_completion(fri, complete_callback,
			NULL , &fri->completion);
		if (r < 0) {
			log_err("rados_aio_create_completion failed.\n");
			goto failed;
		}
		fri->write_op = rados_create_write_op();
		if (fri->write_op == NULL) {
			log_err("rados_create_write_op failed.\n");
			goto failed_comp;
		}
		rados_write_op_zero(fri->write_op, io_u->offset,
			io_u->xfer_buflen);
		r = rados_aio_write_op_operate(fri->write_op, rados->io_ctx,
			fri->completion, object, NULL, 0);
		if (r < 0) {
			log_err("rados_aio_write_op_operate failed.\n");
			goto failed_write_op;
		}
		rados->ops_scheduled++;
		return FIO_Q_QUEUED;
	 }

	log_err("WARNING: Only DDIR_READ, DDIR_WRITE and DDIR_TRIM are supported!");

failed_write_op:
	rados_release_write_op(fri->write_op);
failed_comp:
	rados_aio_release(fri->completion);
failed:
	io_u->error = -r;
	td_verror(td, io_u->error, "xfer");
	return FIO_Q_COMPLETED;
}

static struct io_u *fio_rados_event(struct thread_data *td, int event)
{
	struct rados_data *rados = td->io_ops_data;
	return rados->aio_events[event];
}

int fio_rados_getevents(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	struct rados_data *rados = td->io_ops_data;
	unsigned int events = 0;
	struct fio_rados_iou *fri;

	pthread_mutex_lock(&rados->completed_lock);
	while (events < min) {
		while (flist_empty(&rados->completed_operations)) {
			pthread_cond_wait(&rados->completed_more_io, &rados->completed_lock);
		}
		assert(!flist_empty(&rados->completed_operations));
		
		fri = flist_first_entry(&rados->completed_operations, struct fio_rados_iou, list);
		assert(fri->completion);
		assert(rados_aio_is_complete(fri->completion));
		if (fri->write_op != NULL) {
			rados_release_write_op(fri->write_op);
			fri->write_op = NULL;
		}
		rados_aio_release(fri->completion);
		fri->completion = NULL;

		rados->aio_events[events] = fri->io_u;
		events ++;
		flist_del(&fri->list);
		if (events >= max) break;
	}
	pthread_mutex_unlock(&rados->completed_lock);
	return events;
}

static int fio_rados_setup(struct thread_data *td)
{
	struct rados_data *rados = NULL;
	int r;
	/* allocate engine specific structure to deal with librados. */
	r = _fio_setup_rados_data(td, &rados);
	if (r) {
		log_err("fio_setup_rados_data failed.\n");
		goto cleanup;
	}
	td->io_ops_data = rados;

	/* Force single process mode.
	*/
	td->o.use_thread = 1;

	/* connect in the main thread to determine to determine
	* the size of the given RADOS block device. And disconnect
	* later on.
	*/
	r = _fio_rados_connect(td);
	if (r) {
		log_err("fio_rados_connect failed.\n");
		goto cleanup;
	}
	rados->connected = true;

	return 0;
cleanup:
	fio_rados_cleanup(td);
	return r;
}

/* open/invalidate are noops. we set the FIO_DISKLESSIO flag in ioengine_ops to
   prevent fio from creating the files
*/
static int fio_rados_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}
static int fio_rados_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static void fio_rados_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rados_iou *fri = io_u->engine_data;

	if (fri) {
		io_u->engine_data = NULL;
		fri->td = NULL;
		if (fri->completion)
			rados_aio_release(fri->completion);
		if (fri->write_op)
			rados_release_write_op(fri->write_op);
		free(fri);
	}
}

static int fio_rados_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_rados_iou *fri;
	fri = calloc(1, sizeof(*fri));
	fri->io_u = io_u;
	fri->td = td;
	INIT_FLIST_HEAD(&fri->list);
	io_u->engine_data = fri;
	return 0;
}

/* ioengine_ops for get_ioengine() */
FIO_STATIC struct ioengine_ops ioengine = {
	.name = "rados",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO,
	.setup			= fio_rados_setup,
	.queue			= fio_rados_queue,
	.getevents		= fio_rados_getevents,
	.event			= fio_rados_event,
	.cleanup		= fio_rados_cleanup,
	.open_file		= fio_rados_open,
	.invalidate		= fio_rados_invalidate,
	.options		= options,
	.io_u_init		= fio_rados_io_u_init,
	.io_u_free		= fio_rados_io_u_free,
	.option_struct_size	= sizeof(struct rados_options),
};

static void fio_init fio_rados_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_rados_unregister(void)
{
	unregister_ioengine(&ioengine);
}
