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
 * Note that the structure is exported, so that fio can get it via
 * dlsym(..., "ioengine");
 */
struct ioengine_ops ioengine = {
	.name		= "engine_name",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_skeleton_init,
	.prep		= fio_skeleton_prep,
	.queue		= fio_skeleton_queue,
	.getevents	= fio_skeleton_getevents,
	.event		= fio_skeleton_event,
	.cleanup	= fio_skeleton_cleanup,
};
