/*
 * null engine - doesn't do any transfers. Used to test fio.
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
	struct io_u *last_io_u;
};

static int fio_null_getevents(struct thread_data *td, int fio_unused min,
			      int max, struct timespec fio_unused *t)
{
	assert(max <= 1);

	if (list_empty(&td->io_u_busylist))
		return 0;

	return 1;
}

static struct io_u *fio_null_event(struct thread_data *td, int event)
{
	struct null_data *nd = td->io_ops->data;

	assert(event == 0);

	return nd->last_io_u;
}

static int fio_null_queue(struct thread_data *td, struct io_u *io_u)
{
	struct null_data *nd = td->io_ops->data;

	io_u->resid = 0;
	io_u->error = 0;
	nd->last_io_u = io_u;
	return 0;
}

static void fio_null_cleanup(struct thread_data *td)
{
	if (td->io_ops->data) {
		free(td->io_ops->data);
		td->io_ops->data = NULL;
	}
}

static int fio_null_init(struct thread_data *td)
{
	struct null_data *nd = malloc(sizeof(*nd));

	nd->last_io_u = NULL;
	td->io_ops->data = nd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "null",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_null_init,
	.queue		= fio_null_queue,
	.getevents	= fio_null_getevents,
	.event		= fio_null_event,
	.cleanup	= fio_null_cleanup,
	.flags		= FIO_SYNCIO,
};

static void fio_init fio_null_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_null_unregister(void)
{
	unregister_ioengine(&ioengine);
}
