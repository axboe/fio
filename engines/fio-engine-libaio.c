/*
 * native linux aio io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

#ifdef FIO_HAVE_LIBAIO

#define ev_to_iou(ev)	(struct io_u *) ((unsigned long) (ev)->obj)

struct libaio_data {
	io_context_t aio_ctx;
	struct io_event *aio_events;
};

static int fio_libaio_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_READ)
		io_prep_pread(&io_u->iocb, f->fd, io_u->buf, io_u->buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		io_prep_pwrite(&io_u->iocb, f->fd, io_u->buf, io_u->buflen, io_u->offset);
	else if (io_u->ddir == DDIR_SYNC)
		io_prep_fsync(&io_u->iocb, f->fd);
	else
		return 1;

	return 0;
}

static struct io_u *fio_libaio_event(struct thread_data *td, int event)
{
	struct libaio_data *ld = td->io_ops->data;

	return ev_to_iou(ld->aio_events + event);
}

static int fio_libaio_getevents(struct thread_data *td, int min, int max,
				struct timespec *t)
{
	struct libaio_data *ld = td->io_ops->data;
	long r;

	do {
		r = io_getevents(ld->aio_ctx, min, max, ld->aio_events, t);
		if (r == -EAGAIN) {
			usleep(100);
			continue;
		} else if (r == -EINTR)
			continue;
		else if (r != 0)
			break;
	} while (1);

	if (r < 0)
		r = -r;

	return (int) r;
}

static int fio_libaio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_ops->data;
	struct iocb *iocb = &io_u->iocb;
	long ret;

	do {
		ret = io_submit(ld->aio_ctx, 1, &iocb);
		if (ret == 1)
			return 0;
		else if (ret == -EAGAIN || !ret)
			usleep(100);
		else if (ret == -EINTR)
			continue;
		else
			break;
	} while (1);

	if (ret <= 0) {
		io_u->resid = io_u->buflen;
		io_u->error = -ret;
		return 1;
	}

	return 0;
}

static int fio_libaio_cancel(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_ops->data;

	return io_cancel(ld->aio_ctx, &io_u->iocb, ld->aio_events);
}

static void fio_libaio_cleanup(struct thread_data *td)
{
	struct libaio_data *ld = td->io_ops->data;

	if (ld) {
		io_destroy(ld->aio_ctx);
		if (ld->aio_events)
			free(ld->aio_events);

		free(ld);
		td->io_ops->data = NULL;
	}
}

static int fio_libaio_init(struct thread_data *td)
{
	struct libaio_data *ld = malloc(sizeof(*ld));

	memset(ld, 0, sizeof(*ld));
	if (io_queue_init(td->iodepth, &ld->aio_ctx)) {
		td_verror(td, errno);
		free(ld);
		return 1;
	}

	ld->aio_events = malloc(td->iodepth * sizeof(struct io_event));
	memset(ld->aio_events, 0, td->iodepth * sizeof(struct io_event));
	td->io_ops->data = ld;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "libaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libaio_init,
	.prep		= fio_libaio_prep,
	.queue		= fio_libaio_queue,
	.cancel		= fio_libaio_cancel,
	.getevents	= fio_libaio_getevents,
	.event		= fio_libaio_event,
	.cleanup	= fio_libaio_cleanup,
};

#else /* FIO_HAVE_LIBAIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_libaio_init(struct thread_data fio_unused *td)
{
	fprintf(stderr, "fio: libaio not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "libaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libaio_init,
};

#endif

static void fio_init fio_libaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
