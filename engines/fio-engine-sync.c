/*
 * regular read/write sync io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

struct syncio_data {
	struct io_u *last_io_u;
};

static int fio_syncio_getevents(struct thread_data *td, int fio_unused min,
				int max, struct timespec fio_unused *t)
{
	assert(max <= 1);

	/*
	 * we can only have one finished io_u for sync io, since the depth
	 * is always 1
	 */
	if (list_empty(&td->io_u_busylist))
		return 0;

	return 1;
}

static struct io_u *fio_syncio_event(struct thread_data *td, int event)
{
	struct syncio_data *sd = td->io_ops->data;

	assert(event == 0);

	return sd->last_io_u;
}

static int fio_syncio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_SYNC)
		return 0;
	if (io_u->offset == f->last_completed_pos)
		return 0;

	if (lseek(f->fd, io_u->offset, SEEK_SET) == -1) {
		td_verror(td, errno);
		return 1;
	}

	return 0;
}

static int fio_syncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_ops->data;
	struct fio_file *f = io_u->file;
	unsigned int ret;

	if (io_u->ddir == DDIR_READ)
		ret = read(f->fd, io_u->buf, io_u->buflen);
	else if (io_u->ddir == DDIR_WRITE)
		ret = write(f->fd, io_u->buf, io_u->buflen);
	else
		ret = fsync(f->fd);

	if (ret != io_u->buflen) {
		if (ret > 0) {
			io_u->resid = io_u->buflen - ret;
			io_u->error = EIO;
		} else
			io_u->error = errno;
	}

	if (!io_u->error)
		sd->last_io_u = io_u;

	return io_u->error;
}

static void fio_syncio_cleanup(struct thread_data *td)
{
	if (td->io_ops->data) {
		free(td->io_ops->data);
		td->io_ops->data = NULL;
	}
}

static int fio_syncio_init(struct thread_data *td)
{
	struct syncio_data *sd = malloc(sizeof(*sd));

	sd->last_io_u = NULL;
	td->io_ops->data = sd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "sync",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_syncio_init,
	.prep		= fio_syncio_prep,
	.queue		= fio_syncio_queue,
	.getevents	= fio_syncio_getevents,
	.event		= fio_syncio_event,
	.cleanup	= fio_syncio_cleanup,
	.flags		= FIO_SYNCIO,
};

static void fio_init fio_syncio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_syncio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
