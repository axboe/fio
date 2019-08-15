/*
 * NBD engine
 *
 * IO engine that talks to an NBD server.
 *
 * Copyright (C) 2019 Red Hat Inc.
 * Written by Richard W.M. Jones <rjones@redhat.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <libnbd.h>

#include "../fio.h"
#include "../optgroup.h"

/* Actually this differs across servers, but for nbdkit ... */
#define NBD_MAX_REQUEST_SIZE (64 * 1024 * 1024)

/* Storage for the NBD handle. */
struct nbd_data {
	struct nbd_handle *nbd;
	int debug;

	/* The list of completed io_u structs. */
	struct io_u **completed;
	size_t nr_completed;
};

/* Options. */
struct nbd_options {
	void *padding;
	char *uri;
};

static struct fio_option options[] = {
	{
		.name	= "uri",
		.lname	= "NBD URI",
		.help	= "Name of NBD URI",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NBD,
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct nbd_options, uri),
	},
	{
		.name	= NULL,
	},
};

/* Alocates nbd_data. */
static int nbd_setup(struct thread_data *td)
{
	struct nbd_data *nbd_data;
	struct nbd_options *o = td->eo;
	struct fio_file *f;
	int r;
	int64_t size;

	nbd_data = calloc(1, sizeof(*nbd_data));
	if (!nbd_data) {
		td_verror(td, errno, "calloc");
		return 1;
	}
	td->io_ops_data = nbd_data;

	/* Pretend to deal with files.	See engines/rbd.c */
	if (!td->files_index) {
		add_file(td, "nbd", 0, 0);
		td->o.nr_files = td->o.nr_files ? : 1;
		td->o.open_files++;
	}
	f = td->files[0];

	nbd_data->nbd = nbd_create();
	if (!nbd_data->nbd) {
		log_err("fio: nbd_create: %s\n", nbd_get_error());
		return 1;
	}

	/* Get the debug flag which can be set through LIBNBD_DEBUG=1. */
	nbd_data->debug = nbd_get_debug(nbd_data->nbd);

	/* Connect synchronously here so we can check for the size and
	 * in future other properties of the server.
	 */
	if (!o->uri) {
		log_err("fio: nbd: uri parameter was not specified\n");
		return 1;
	}
	r = nbd_connect_uri(nbd_data->nbd, o->uri);
	if (r == -1) {
		log_err("fio: nbd_connect_uri: %s\n", nbd_get_error());
		return 1;
	}
	size = nbd_get_size(nbd_data->nbd);
	if (size == -1) {
		log_err("fio: nbd_get_size: %s\n", nbd_get_error());
		return 1;
	}

	f->real_file_size = size;

	nbd_close (nbd_data->nbd);
	nbd_data->nbd = NULL;

	return 0;
}

/* Closes socket and frees nbd_data -- the opposite of nbd_setup. */
static void nbd_cleanup(struct thread_data *td)
{
	struct nbd_data *nbd_data = td->io_ops_data;

	if (nbd_data) {
		if (nbd_data->nbd)
			nbd_close(nbd_data->nbd);
		free(nbd_data);
	}
}

/* Connect to the server from each thread. */
static int nbd_init(struct thread_data *td)
{
	struct nbd_options *o = td->eo;
	struct nbd_data *nbd_data = td->io_ops_data;
	int r;

	if (!o->uri) {
		log_err("fio: nbd: uri parameter was not specified\n");
		return 1;
	}

	nbd_data->nbd = nbd_create();
	if (!nbd_data->nbd) {
		log_err("fio: nbd_create: %s\n", nbd_get_error());
		return 1;
	}
	/* This is actually a synchronous connect and handshake. */
	r = nbd_connect_uri(nbd_data->nbd, o->uri);
	if (r == -1) {
		log_err("fio: nbd_connect_uri: %s\n", nbd_get_error());
		return 1;
	}

	log_info("fio: connected to NBD server\n");
	return 0;
}

/* A command in flight has been completed. */
static int cmd_completed (void *vp, int *error)
{
	struct io_u *io_u;
	struct nbd_data *nbd_data;
	struct io_u **completed;

	io_u = vp;
	nbd_data = io_u->engine_data;

	if (nbd_data->debug)
		log_info("fio: nbd: command completed\n");

	if (*error != 0)
		io_u->error = *error;
	else
		io_u->error = 0;

	/* Add this completion to the list so it can be picked up
	 * later by ->event.
	 */
	completed = realloc(nbd_data->completed,
			    sizeof(struct io_u *) *
			    (nbd_data->nr_completed+1));
	if (completed == NULL) {
		io_u->error = errno;
		return 0;
	}

	nbd_data->completed = completed;
	nbd_data->completed[nbd_data->nr_completed] = io_u;
	nbd_data->nr_completed++;

	return 0;
}

/* Begin read or write request. */
static enum fio_q_status nbd_queue(struct thread_data *td,
				   struct io_u *io_u)
{
	struct nbd_data *nbd_data = td->io_ops_data;
	nbd_completion_callback completion = { .callback = cmd_completed,
					       .user_data = io_u };
	int r;

	fio_ro_check(td, io_u);

	io_u->engine_data = nbd_data;

	if (io_u->ddir == DDIR_WRITE || io_u->ddir == DDIR_READ)
		assert(io_u->xfer_buflen <= NBD_MAX_REQUEST_SIZE);

	switch (io_u->ddir) {
	case DDIR_READ:
		r = nbd_aio_pread(nbd_data->nbd,
				  io_u->xfer_buf, io_u->xfer_buflen,
				  io_u->offset, completion, 0);
		break;
	case DDIR_WRITE:
		r = nbd_aio_pwrite(nbd_data->nbd,
				   io_u->xfer_buf, io_u->xfer_buflen,
				   io_u->offset, completion, 0);
		break;
	case DDIR_TRIM:
		r = nbd_aio_trim(nbd_data->nbd, io_u->xfer_buflen,
				 io_u->offset, completion, 0);
		break;
	case DDIR_SYNC:
		/* XXX We could probably also handle
		 * DDIR_SYNC_FILE_RANGE with a bit of effort.
		 */
		r = nbd_aio_flush(nbd_data->nbd, completion, 0);
		break;
	default:
		io_u->error = EINVAL;
		return FIO_Q_COMPLETED;
	}

	if (r == -1) {
		/* errno is optional information on libnbd error path;
		 * if it's 0, set it to a default value
		 */
		io_u->error = nbd_get_errno();
		if (io_u->error == 0)
			io_u->error = EIO;
		return FIO_Q_COMPLETED;
	}

	if (nbd_data->debug)
		log_info("fio: nbd: command issued\n");
	io_u->error = 0;
	return FIO_Q_QUEUED;
}

static unsigned retire_commands(struct nbd_handle *nbd)
{
	int64_t cookie;
	unsigned r = 0;

	while ((cookie = nbd_aio_peek_command_completed(nbd)) > 0) {
		/* Ignore the return value.  cmd_completed has already
		 * checked for an error and set io_u->error.  We only
		 * have to call this to retire the command.
		 */
		nbd_aio_command_completed(nbd, cookie);
		r++;
	}

	if (nbd_get_debug(nbd))
		log_info("fio: nbd: %u commands retired\n", r);
	return r;
}

static int nbd_getevents(struct thread_data *td, unsigned int min,
			 unsigned int max, const struct timespec *t)
{
	struct nbd_data *nbd_data = td->io_ops_data;
	int r;
	unsigned events = 0;
	int timeout;

	/* XXX This handling of timeout is wrong because it will wait
	 * for up to loop iterations * timeout.
	 */
	timeout = !t ? -1 : t->tv_sec * 1000 + t->tv_nsec / 1000000;

	while (events < min) {
		r = nbd_poll(nbd_data->nbd, timeout);
		if (r == -1) {
			/* error in poll */
			log_err("fio: nbd_poll: %s\n", nbd_get_error());
			return -1;
		}
		else {
			/* poll made progress */
			events += retire_commands(nbd_data->nbd);
		}
	}

	return events;
}

static struct io_u *nbd_event(struct thread_data *td, int event)
{
	struct nbd_data *nbd_data = td->io_ops_data;

	if (nbd_data->nr_completed == 0)
		return NULL;

	/* XXX We ignore the event number and assume fio calls us
	 * exactly once for [0..nr_events-1].
	 */
	nbd_data->nr_completed--;
	return nbd_data->completed[nbd_data->nr_completed];
}

static int nbd_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	io_u->engine_data = NULL;
	return 0;
}

static void nbd_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	/* Nothing needs to be done. */
}

static int nbd_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static int nbd_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "nbd",
	.version		= FIO_IOOPS_VERSION,
	.options		= options,
	.option_struct_size	= sizeof(struct nbd_options),
	.flags			= FIO_DISKLESSIO | FIO_NOEXTEND,

	.setup			= nbd_setup,
	.init			= nbd_init,
	.cleanup		= nbd_cleanup,
	.queue			= nbd_queue,
	.getevents		= nbd_getevents,
	.event			= nbd_event,
	.io_u_init		= nbd_io_u_init,
	.io_u_free		= nbd_io_u_free,

	.open_file		= nbd_open_file,
	.invalidate		= nbd_invalidate,
};

static void fio_init fio_nbd_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_nbd_unregister(void)
{
	unregister_ioengine(&ioengine);
}
