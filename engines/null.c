/*
 * null engine
 *
 * IO engine that doesn't do any real IO transfers, it just pretends to.
 * The main purpose is to test fio itself.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

struct null_data {
	struct io_u **io_us;
	int queued;
	int events;
};

static struct io_u *fio_null_event(struct thread_data *td, int event)
{
	struct null_data *nd = td->io_ops->data;

	return nd->io_us[event];
}

static int fio_null_getevents(struct thread_data *td, int min_events,
			      int fio_unused max, struct timespec fio_unused *t)
{
	struct null_data *nd = td->io_ops->data;
	int ret = 0;
	
	if (min_events) {
		ret = nd->events;
		nd->events = 0;
	}

	return ret;
}

static int fio_null_commit(struct thread_data *td)
{
	struct null_data *nd = td->io_ops->data;

	nd->events += nd->queued;
	nd->queued = 0;
	return 0;
}

static int fio_null_queue(struct thread_data fio_unused *td, struct io_u *io_u)
{
	struct null_data *nd = td->io_ops->data;

	if (td->io_ops->flags & FIO_SYNCIO)
		return FIO_Q_COMPLETED;

	nd->io_us[nd->queued++] = io_u;
	return FIO_Q_QUEUED;
}

static int fio_null_setup(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	if (!td->total_file_size) {
		log_err("fio: need size= set\n");
		return 1;
	}

	td->io_size = td->total_file_size;
	td->total_io_size = td->io_size;

	for_each_file(td, f, i) {
		f->real_file_size = td->total_io_size / td->nr_files;
		f->file_size = f->real_file_size;
	}

	return 0;
}

static int fio_null_open(struct thread_data fio_unused *td,
			 struct fio_file fio_unused *f)
{
	f->fd = 0;
	return 0;
}

static void fio_null_cleanup(struct thread_data *td)
{
	struct null_data *nd = td->io_ops->data;

	if (nd) {
		if (nd->io_us)
			free(nd->io_us);
		free(nd);
		td->io_ops->data = NULL;
	}
}

static int fio_null_init(struct thread_data *td)
{
	struct null_data *nd = malloc(sizeof(*nd));

	memset(nd, 0, sizeof(*nd));

	if (td->iodepth != 1) {
		nd->io_us = malloc(td->iodepth * sizeof(struct io_u *));
		memset(nd->io_us, 0, td->iodepth * sizeof(struct io_u *));
	} else
		td->io_ops->flags |= FIO_SYNCIO;

	td->io_ops->data = nd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "null",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_null_setup,
	.queue		= fio_null_queue,
	.commit		= fio_null_commit,
	.getevents	= fio_null_getevents,
	.event		= fio_null_event,
	.init		= fio_null_init,
	.cleanup	= fio_null_cleanup,
	.open_file	= fio_null_open,
	.flags		= FIO_DISKLESSIO,
};

static void fio_init fio_null_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_null_unregister(void)
{
	unregister_ioengine(&ioengine);
}
