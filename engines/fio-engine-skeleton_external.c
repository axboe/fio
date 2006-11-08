/*
 * Skeleton for a sample external io engine
 *
 * Should be compiled with:
 *
 * gcc -Wall -O2 -g -shared -rdynamic -fPIC -o engine.o engine.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

/*
 * The core of the module is identical to the ones included with fio,
 * read those. You cannot use register_ioengine() and unregister_ioengine()
 * for external modules, they should be gotten through dlsym()
 */

/*
 * The ->event() hook is called to match an event number with an io_u.
 * After the core has called ->getevents() and it has returned eg 3,
 * the ->event() hook must return the 3 events that have completed for
 * subsequent calls to ->event() with [0-2]. Required.
 */
static struct io_u *fio_skeleton_event(struct thread_data *td, int event)
{
	return NULL;
}

/*
 * The ->getevents() hook is used to reap completion events from an async
 * io engine. It returns the number of completed events since the last call,
 * which may then be retrieved by calling the ->event() hook with the event
 * numbers. Required.
 */
static int fio_skeleton_getevents(struct thread_data *td, int min, int max,
				  struct timespec *t)
{
	return 0;
}

/*
 * The ->cancel() hook attempts to cancel the io_u. Only relevant for
 * async io engines, and need not be supported.
 */
static int fio_skeleton_cancel(struct thread_data *td, struct io_u *io_u)
{
	return 0;
}

/*
 * The ->queue() hook is responsible for initiating io on the io_u
 * being passed in. If the io engine is a synchronous one, io may complete
 * before ->queue() returns. Required.
 */
static int fio_skeleton_queue(struct thread_data *td, struct io_u *io_u)
{
	return 0;
}

/*
 * The ->prep() function is called for each io_u prior to being submitted
 * with ->queue(). This hook allows the io engine to perform any
 * preperatory actions on the io_u, before being submitted. Not required.
 */
static int fio_skeleton_prep(struct thread_data *td, struct io_u *io_u)
{
	return 0;
}

/*
 * The init function is called once per thread/process, and should set up
 * any structures that this io engine requires to keep track of io. Not
 * required.
 */
static int fio_skeleton_init(struct thread_data *td)
{
	return 0;
}

/*
 * This is paired with the ->init() funtion and is called when a thread is
 * done doing io. Should tear down anything setup by the ->init() function.
 * Not required.
 */
static void fio_skeleton_cleanup(struct thread_data *td)
{
}

/*
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine");
 */
struct ioengine_ops ioengine = {
	.name		= "engine_name",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_skeleton_init,
	.prep		= fio_skeleton_prep,
	.queue		= fio_skeleton_queue,
	.cancel		= fio_skeleton_cancel,
	.getevents	= fio_skeleton_getevents,
	.event		= fio_skeleton_event,
	.cleanup	= fio_skeleton_cleanup,
};
