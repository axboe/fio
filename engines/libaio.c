/*
 * libaio engine
 *
 * IO engine using the Linux native aio interface.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"

#ifdef FIO_HAVE_LIBAIO

#define ev_to_iou(ev)	(struct io_u *) ((unsigned long) (ev)->obj)

struct libaio_data {
	io_context_t aio_ctx;
	struct io_event *aio_events;
	struct iocb **iocbs;
	struct io_u **io_us;
	int iocbs_nr;
};

static int fio_libaio_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_READ)
		io_prep_pread(&io_u->iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		io_prep_pwrite(&io_u->iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_SYNC)
		io_prep_fsync(&io_u->iocb, f->fd);
	else
		return 1;

	return 0;
}

static struct io_u *fio_libaio_event(struct thread_data *td, int event)
{
	struct libaio_data *ld = td->io_ops->data;
	struct io_event *ev;
	struct io_u *io_u;

	ev = ld->aio_events + event;
	io_u = ev_to_iou(ev);

	if (ev->res != io_u->xfer_buflen) {
		if (ev->res > io_u->xfer_buflen)
			io_u->error = -ev->res;
		else
			io_u->resid = io_u->xfer_buflen - ev->res;
	} else
		io_u->error = 0;

	return io_u;
}

static int fio_libaio_getevents(struct thread_data *td, int min, int max,
				struct timespec *t)
{
	struct libaio_data *ld = td->io_ops->data;
	long r;

	do {
		r = io_getevents(ld->aio_ctx, min, max, ld->aio_events, t);
		if (r >= min)
			break;
		else if (r == -EAGAIN) {
			usleep(100);
			continue;
		} else if (r == -EINTR)
			continue;
		else if (r != 0)
			break;
	} while (1);

	return r;
}

static int fio_libaio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_ops->data;

	fio_ro_check(td, io_u);

	if (ld->iocbs_nr == (int) td->o.iodepth)
		return FIO_Q_BUSY;

	/*
	 * fsync is tricky, since it can fail and we need to do it
	 * serialized with other io. the reason is that linux doesn't
	 * support aio fsync yet. So return busy for the case where we
	 * have pending io, to let fio complete those first.
	 */
	if (io_u->ddir == DDIR_SYNC) {
		if (ld->iocbs_nr)
			return FIO_Q_BUSY;
		if (fsync(io_u->file->fd) < 0)
			io_u->error = errno;

		return FIO_Q_COMPLETED;
	}

	ld->iocbs[ld->iocbs_nr] = &io_u->iocb;
	ld->io_us[ld->iocbs_nr] = io_u;
	ld->iocbs_nr++;
	return FIO_Q_QUEUED;
}

static void fio_libaio_queued(struct thread_data *td, struct io_u **io_us,
			      unsigned int nr)
{
	struct timeval now;
	unsigned int i;

	fio_gettime(&now, NULL);

	for (i = 0; i < nr; i++) {
		struct io_u *io_u = io_us[i];

		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);
	}
}

static int fio_libaio_commit(struct thread_data *td)
{
	struct libaio_data *ld = td->io_ops->data;
	struct iocb **iocbs;
	struct io_u **io_us;
	int ret, iocbs_nr;

	if (!ld->iocbs_nr)
		return 0;

	iocbs_nr = ld->iocbs_nr;
	io_us = ld->io_us;
	iocbs = ld->iocbs;
	do {
		ret = io_submit(ld->aio_ctx, iocbs_nr, iocbs);
		if (ret == iocbs_nr) {
			fio_libaio_queued(td, io_us, ret);
			ret = 0;
			break;
		} else if (ret > 0) {
			fio_libaio_queued(td, io_us, ret);
			io_us += ret;
			iocbs += ret;
			iocbs_nr -= ret;
			continue;
		} else if (ret == -EAGAIN || !ret)
			usleep(100);
		else if (ret == -EINTR)
			continue;
		else
			break;
	} while (1);

	if (!ret)
		ld->iocbs_nr = 0;

	return ret;
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
		free(ld->aio_events);
		free(ld->iocbs);
		free(ld->io_us);
		free(ld);
		td->io_ops->data = NULL;
	}
}

static int fio_libaio_init(struct thread_data *td)
{
	struct libaio_data *ld = malloc(sizeof(*ld));
	static int warn_print;
	int err;

	if (td->o.iodepth > 1 && !td->o.odirect && !warn_print) {
		log_info("fio: libaio engine is only async for non-buffered IO\n");
		warn_print = 1;
	}

	memset(ld, 0, sizeof(*ld));

	err = io_queue_init(td->o.iodepth, &ld->aio_ctx);
	if (err) {
		td_verror(td, -err, "io_queue_init");
		free(ld);
		return 1;
	}

	ld->aio_events = malloc(td->o.iodepth * sizeof(struct io_event));
	memset(ld->aio_events, 0, td->o.iodepth * sizeof(struct io_event));
	ld->iocbs = malloc(td->o.iodepth * sizeof(struct iocb *));
	memset(ld->iocbs, 0, sizeof(struct iocb *));
	ld->io_us = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(ld->io_us, 0, td->o.iodepth * sizeof(struct io_u *));
	ld->iocbs_nr = 0;

	td->io_ops->data = ld;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "libaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libaio_init,
	.prep		= fio_libaio_prep,
	.queue		= fio_libaio_queue,
	.commit		= fio_libaio_commit,
	.cancel		= fio_libaio_cancel,
	.getevents	= fio_libaio_getevents,
	.event		= fio_libaio_event,
	.cleanup	= fio_libaio_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
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
