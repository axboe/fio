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

static int fio_null_queue(struct thread_data fio_unused *td, struct io_u *io_u)
{
	io_u->resid = 0;
	io_u->error = 0;
	return FIO_Q_COMPLETED;
}

static struct ioengine_ops ioengine = {
	.name		= "null",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_null_queue,
	.flags		= FIO_SYNCIO | FIO_NULLIO,
};

static void fio_init fio_null_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_null_unregister(void)
{
	unregister_ioengine(&ioengine);
}
