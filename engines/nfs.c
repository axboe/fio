#include <stdlib.h>
#include <poll.h>
#include <nfsc/libnfs.h>
#include <nfsc/libnfs-raw.h>
#include <nfsc/libnfs-raw-mount.h>

#include "../fio.h"
#include "../optgroup.h"

enum nfs_op_type {
	NFS_READ_WRITE = 0,
	NFS_STAT_MKDIR_RMDIR,
	NFS_STAT_TOUCH_RM,
};

struct fio_libnfs_options {
	struct nfs_context *context;
	char *nfs_url;
	/* nfs_callback needs this info, but doesn't have fio td structure to
	 * pull it from
	 */
	unsigned int queue_depth;

	/* the following implement a circular queue of outstanding IOs */

	/* IOs issued to libnfs, that have not returned yet */
	int outstanding_events;
	/* event last returned via fio_libnfs_event */
	int prev_requested_event_index;
	int next_buffered_event; /* round robin-pointer within events[] */
	int buffered_event_count; /* IOs completed by libnfs, waiting for FIO */
	int free_event_buffer_index; /* next free buffer */
	struct io_u**events;
};

struct nfs_data {
	struct nfsfh *nfsfh;
	struct fio_libnfs_options *options;
};

static struct fio_option options[] = {
	{
		.name	= "nfs_url",
		.lname	= "nfs_url",
		.type	= FIO_OPT_STR_STORE,
		.help	= "URL in libnfs format, eg nfs://<server|ipv4|"
			  "ipv6>/path[?arg=val[&arg=val]*]",
		.off1	= offsetof(struct fio_libnfs_options, nfs_url),
		.category = FIO_OPT_C_ENGINE,
		.group	= __FIO_OPT_G_NFS,
	},
	{
		.name     = NULL,
	},
};

static struct io_u *fio_libnfs_event(struct thread_data *td, int event)
{
	struct fio_libnfs_options *o = td->eo;
	struct io_u *io_u = o->events[o->next_buffered_event];

	assert(o->events[o->next_buffered_event]);
	o->events[o->next_buffered_event] = NULL;
	o->next_buffered_event = (o->next_buffered_event + 1) % td->o.iodepth;

	/* validate our state machine */
	assert(o->buffered_event_count);
	o->buffered_event_count--;
	assert(io_u);

	/* assert that fio_libnfs_event is being called in sequential fashion */
	assert(event == 0 || o->prev_requested_event_index + 1 == event);
	if (o->buffered_event_count == 0)
		o->prev_requested_event_index = -1;
	else
		o->prev_requested_event_index = event;
	return io_u;
}

/*
 * fio core logic seems to stop calling this event-loop if we ever return with
 * 0 events
 */
#define SHOULD_WAIT(td, o, flush)			\
 	((o)->outstanding_events == (td)->o.iodepth ||	\
		(flush && (o)->outstanding_events))

static int nfs_event_loop(struct thread_data *td, bool flush)
{
	struct fio_libnfs_options *o = td->eo;
	struct pollfd pfds[1]; /* nfs:0 */

	/* we already have stuff queued for fio, no need to waste cpu on poll() */
	if (o->buffered_event_count)
		return o->buffered_event_count;

	do {
		int timeout = SHOULD_WAIT(td, o, flush) ? -1 : 0;
		int ret = 0;

		pfds[0].fd = nfs_get_fd(o->context);
		pfds[0].events = nfs_which_events(o->context);
		ret = poll(&pfds[0], 1, timeout);
		if (ret < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			log_err("nfs: failed to poll events: %s\n", strerror(errno));
			break;
		}

		ret = nfs_service(o->context, pfds[0].revents);
		if (ret < 0) {
			log_err("nfs: socket is in an unrecoverable error state.\n");
			break;
		}
	} while (SHOULD_WAIT(td, o, flush));

	return o->buffered_event_count;
}

static int fio_libnfs_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	return nfs_event_loop(td, false);
}

static void nfs_callback(int res, struct nfs_context *nfs, void *data,
			 void *private_data)
{
	struct io_u *io_u = private_data;
	struct nfs_data *nfs_data = io_u->file->engine_data;
	struct fio_libnfs_options *o = nfs_data->options;
	if (res < 0) {
		log_err("Failed NFS operation(code:%d): %s\n", res,
						nfs_get_error(o->context));
		io_u->error = -res;
		/* res is used for read math below, don't want to pass negative
		 * there
		 */
		res = 0;
	} else if (io_u->ddir == DDIR_READ) {
		memcpy(io_u->buf, data, res);
		if (res == 0)
			log_err("Got NFS EOF, this is probably not expected\n");
	}
	/* fio uses resid to track remaining data */
	io_u->resid = io_u->xfer_buflen - res;

	assert(!o->events[o->free_event_buffer_index]);
	o->events[o->free_event_buffer_index] = io_u;
	o->free_event_buffer_index = (o->free_event_buffer_index + 1) % o->queue_depth;
	o->outstanding_events--;
	o->buffered_event_count++;
}

static int queue_write(struct fio_libnfs_options *o, struct io_u *io_u)
{
	struct nfs_data *nfs_data = io_u->engine_data;

#ifdef LIBNFS_API_V2
	return nfs_pwrite_async(o->context, nfs_data->nfsfh,
				io_u->buf, io_u->buflen, io_u->offset,
				nfs_callback, io_u);
#else
	return nfs_pwrite_async(o->context, nfs_data->nfsfh, io_u->offset,
				io_u->buflen, io_u->buf, nfs_callback, io_u);
#endif
}

static int queue_read(struct fio_libnfs_options *o, struct io_u *io_u)
{
	struct nfs_data *nfs_data = io_u->engine_data;

#ifdef LIBNFS_API_V2
	return nfs_pread_async(o->context, nfs_data->nfsfh,
				io_u->buf, io_u->buflen, io_u->offset,
				nfs_callback, io_u);
#else
	return nfs_pread_async(o->context, nfs_data->nfsfh, io_u->offset,
				io_u->buflen, nfs_callback, io_u);
#endif
}

static enum fio_q_status fio_libnfs_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct nfs_data *nfs_data = io_u->file->engine_data;
	struct fio_libnfs_options *o = nfs_data->options;
	struct nfs_context *nfs = o->context;
	enum fio_q_status ret = FIO_Q_QUEUED;
	int err;

	io_u->engine_data = nfs_data;
	switch (io_u->ddir) {
	case DDIR_WRITE:
		err = queue_write(o, io_u);
		break;
	case DDIR_READ:
		err = queue_read(o, io_u);
		break;
	case DDIR_TRIM:
		log_err("nfs: trim is not supported");
		err = -1;
		break;
	default:
		log_err("nfs: unhandled io %d\n", io_u->ddir);
		err = -1;
	}
	if (err) {
		log_err("nfs: Failed to queue nfs op: %s\n", nfs_get_error(nfs));
		td->error = 1;
		return FIO_Q_COMPLETED;
	}
	o->outstanding_events++;
	return ret;
}

/*
 * Do a mount if one has not been done before 
 */
static int do_mount(struct thread_data *td, const char *url)
{
	size_t event_size = sizeof(struct io_u **) * td->o.iodepth;
	struct fio_libnfs_options *options = td->eo;
	struct nfs_url *nfs_url = NULL;
	int ret = 0;
	int path_len = 0;
	char *mnt_dir = NULL;

	if (options->context)
		return 0;

	options->context = nfs_init_context();
	if (!options->context) {
		log_err("nfs: failed to init nfs context\n");
		return -1;
	}

	options->events = calloc(1, event_size);

	options->prev_requested_event_index = -1;
	options->queue_depth = td->o.iodepth;

	nfs_url = nfs_parse_url_full(options->context, url);
	path_len = strlen(nfs_url->path);
	mnt_dir = malloc(path_len + strlen(nfs_url->file) + 1);
	strcpy(mnt_dir, nfs_url->path);
	strcpy(mnt_dir + strlen(nfs_url->path), nfs_url->file);
	ret = nfs_mount(options->context, nfs_url->server, mnt_dir);
	free(mnt_dir);
	nfs_destroy_url(nfs_url);
	return ret;
}

static int fio_libnfs_setup(struct thread_data *td)
{
	/* Using threads with libnfs causes fio to hang on exit, lower
	 * performance
	 */
	td->o.use_thread = 0;
	return 0;
}

static void fio_libnfs_cleanup(struct thread_data *td)
{
	struct fio_libnfs_options *o = td->eo;

	nfs_umount(o->context);
	nfs_destroy_context(o->context);
	free(o->events);
}

static int fio_libnfs_open(struct thread_data *td, struct fio_file *f)
{
	struct fio_libnfs_options *options = td->eo;
	struct nfs_data *nfs_data = NULL;
	int flags = 0;
	int ret;

	if (!options->nfs_url) {
		log_err("nfs: nfs_url is a required parameter\n");
		return -1;
	}

	ret = do_mount(td, options->nfs_url);

	if (ret) {
		log_err("nfs: Failed to mount %s with code %d: %s\n",
			options->nfs_url, ret, nfs_get_error(options->context));
		return ret;
	}
	nfs_data = calloc(1, sizeof(struct nfs_data));
	nfs_data->options = options;

	if (td_write(td))
		flags |= O_CREAT | O_RDWR;
	else
		flags |= O_RDWR;

	ret = nfs_open(options->context, f->file_name, flags, &nfs_data->nfsfh);

	if (ret)
		log_err("Failed to open %s: %s\n", f->file_name,
					nfs_get_error(options->context));
	f->engine_data = nfs_data;
	return ret;
}

static int fio_libnfs_close(struct thread_data *td, struct fio_file *f)
{
	struct nfs_data *nfs_data = f->engine_data;
	struct fio_libnfs_options *o = nfs_data->options;
	int ret = 0;

	if (nfs_data->nfsfh)
		ret = nfs_close(o->context, nfs_data->nfsfh);

	free(nfs_data);
	f->engine_data = NULL;
	return ret;
}

static struct ioengine_ops ioengine = {
	.name		= "nfs",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_libnfs_setup,
	.queue		= fio_libnfs_queue,
	.getevents	= fio_libnfs_getevents,
	.event		= fio_libnfs_event,
	.cleanup	= fio_libnfs_cleanup,
	.open_file	= fio_libnfs_open,
	.close_file	= fio_libnfs_close,
	.flags		= FIO_DISKLESSIO | FIO_NOEXTEND | FIO_NODISKUTIL,
	.options	= options,
	.option_struct_size	= sizeof(struct fio_libnfs_options),
};

static void fio_init fio_nfs_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_nfs_unregister(void)
{
	unregister_ioengine(&ioengine);
}
