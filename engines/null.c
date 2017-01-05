/*
 * null engine
 *
 * IO engine that doesn't do any real IO transfers, it just pretends to.
 * The main purpose is to test fio itself.
 *
 * It also can act as external C++ engine - compiled with:
 *
 * g++ -O2 -g -shared -rdynamic -fPIC -o null.so null.c -DFIO_EXTERNAL_ENGINE
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"

struct null_data {
	struct io_u **io_us;
	int queued;
	int events;
};

static struct io_u *fio_null_event(struct thread_data *td, int event)
{
	struct null_data *nd = (struct null_data *) td->io_ops_data;

	return nd->io_us[event];
}

static int fio_null_getevents(struct thread_data *td, unsigned int min_events,
			      unsigned int fio_unused max,
			      const struct timespec fio_unused *t)
{
	struct null_data *nd = (struct null_data *) td->io_ops_data;
	int ret = 0;
	
	if (min_events) {
		ret = nd->events;
		nd->events = 0;
	}

	return ret;
}

static int fio_null_commit(struct thread_data *td)
{
	struct null_data *nd = (struct null_data *) td->io_ops_data;

	if (!nd->events) {
#ifndef FIO_EXTERNAL_ENGINE
		io_u_mark_submit(td, nd->queued);
#endif
		nd->events = nd->queued;
		nd->queued = 0;
	}

	return 0;
}

static int fio_null_queue(struct thread_data *td, struct io_u *io_u)
{
	struct null_data *nd = (struct null_data *) td->io_ops_data;

	fio_ro_check(td, io_u);

	if (td->io_ops->flags & FIO_SYNCIO)
		return FIO_Q_COMPLETED;
	if (nd->events)
		return FIO_Q_BUSY;

	nd->io_us[nd->queued++] = io_u;
	return FIO_Q_QUEUED;
}

static int fio_null_open(struct thread_data fio_unused *td,
			 struct fio_file fio_unused *f)
{
	return 0;
}

static void fio_null_cleanup(struct thread_data *td)
{
	struct null_data *nd = (struct null_data *) td->io_ops_data;

	if (nd) {
		free(nd->io_us);
		free(nd);
	}
}

static int fio_null_init(struct thread_data *td)
{
	struct null_data *nd = (struct null_data *) malloc(sizeof(*nd));

	memset(nd, 0, sizeof(*nd));

	if (td->o.iodepth != 1) {
		nd->io_us = (struct io_u **) malloc(td->o.iodepth * sizeof(struct io_u *));
		memset(nd->io_us, 0, td->o.iodepth * sizeof(struct io_u *));
	} else
		td->io_ops->flags |= FIO_SYNCIO;

	td->io_ops_data = nd;
	return 0;
}

#ifndef __cplusplus
static struct ioengine_ops ioengine = {
	.name		= "null",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_null_queue,
	.commit		= fio_null_commit,
	.getevents	= fio_null_getevents,
	.event		= fio_null_event,
	.init		= fio_null_init,
	.cleanup	= fio_null_cleanup,
	.open_file	= fio_null_open,
	.flags		= FIO_DISKLESSIO | FIO_FAKEIO,
};

static void fio_init fio_null_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_null_unregister(void)
{
	unregister_ioengine(&ioengine);
}

#else

#ifdef FIO_EXTERNAL_ENGINE
extern "C" {
static struct ioengine_ops ioengine;
void get_ioengine(struct ioengine_ops **ioengine_ptr)
{
	*ioengine_ptr = &ioengine;

	ioengine.name           = "cpp_null";
	ioengine.version        = FIO_IOOPS_VERSION;
	ioengine.queue          = fio_null_queue;
	ioengine.commit         = fio_null_commit;
	ioengine.getevents      = fio_null_getevents;
	ioengine.event          = fio_null_event;
	ioengine.init           = fio_null_init;
	ioengine.cleanup        = fio_null_cleanup;
	ioengine.open_file      = fio_null_open;
	ioengine.flags          = FIO_DISKLESSIO | FIO_FAKEIO;
}
}
#endif /* FIO_EXTERNAL_ENGINE */

#endif /* __cplusplus */
