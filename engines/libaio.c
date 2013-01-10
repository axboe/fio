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
#include <libaio.h>

#include "../fio.h"

struct libaio_data {
	io_context_t aio_ctx;
	struct io_event *aio_events;
	struct iocb **iocbs;
	struct io_u **io_us;
	int iocbs_nr;
};

struct libaio_options {
	struct thread_data *td;
	unsigned int userspace_reap;
};

static struct fio_option options[] = {
	{
		.name	= "userspace_reap",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct libaio_options, userspace_reap),
		.help	= "Use alternative user-space reap implementation",
	},
	{
		.name	= NULL,
	},
};

static int fio_libaio_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_READ)
		io_prep_pread(&io_u->iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		io_prep_pwrite(&io_u->iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (ddir_sync(io_u->ddir))
		io_prep_fsync(&io_u->iocb, f->fd);

	return 0;
}

static struct io_u *fio_libaio_event(struct thread_data *td, int event)
{
	struct libaio_data *ld = td->io_ops->data;
	struct io_event *ev;
	struct io_u *io_u;

	ev = ld->aio_events + event;
	io_u = container_of(ev->obj, struct io_u, iocb);

	if (ev->res != io_u->xfer_buflen) {
		if (ev->res > io_u->xfer_buflen)
			io_u->error = -ev->res;
		else
			io_u->resid = io_u->xfer_buflen - ev->res;
	} else
		io_u->error = 0;

	return io_u;
}

struct aio_ring {
	unsigned id;		 /** kernel internal index number */
	unsigned nr;		 /** number of io_events */
	unsigned head;
	unsigned tail;

	unsigned magic;
	unsigned compat_features;
	unsigned incompat_features;
	unsigned header_length;	/** size of aio_ring */

	struct io_event events[0];
};

#define AIO_RING_MAGIC	0xa10a10a1

static int user_io_getevents(io_context_t aio_ctx, unsigned int max,
			     struct io_event *events)
{
	long i = 0;
	unsigned head;
	struct aio_ring *ring = (struct aio_ring*) aio_ctx;

	while (i < max) {
		head = ring->head;

		if (head == ring->tail) {
			/* There are no more completions */
			break;
		} else {
			/* There is another completion to reap */
			events[i] = ring->events[head];
			read_barrier();
			ring->head = (head + 1) % ring->nr;
			i++;
		}
	}

	return i;
}

static int fio_libaio_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, struct timespec *t)
{
	struct libaio_data *ld = td->io_ops->data;
	struct libaio_options *o = td->eo;
	unsigned actual_min = td->o.iodepth_batch_complete == 0 ? 0 : min;
	int r, events = 0;

	do {
		if (o->userspace_reap == 1
		    && actual_min == 0
		    && ((struct aio_ring *)(ld->aio_ctx))->magic
				== AIO_RING_MAGIC) {
			r = user_io_getevents(ld->aio_ctx, max,
				ld->aio_events + events);
		} else {
			r = io_getevents(ld->aio_ctx, actual_min,
				max, ld->aio_events + events, t);
		}
		if (r >= 0)
			events += r;
		else if (r == -EAGAIN)
			usleep(100);
	} while (events < min);

	return r < 0 ? r : events;
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
	if (ddir_sync(io_u->ddir)) {
		if (ld->iocbs_nr)
			return FIO_Q_BUSY;

		do_io_u_sync(td, io_u);
		return FIO_Q_COMPLETED;
	}

	if (io_u->ddir == DDIR_TRIM) {
		if (ld->iocbs_nr)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);
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

	if (!fio_fill_issue_time(td))
		return;

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
	int ret;

	if (!ld->iocbs_nr)
		return 0;

	io_us = ld->io_us;
	iocbs = ld->iocbs;
	do {
		ret = io_submit(ld->aio_ctx, ld->iocbs_nr, iocbs);
		if (ret > 0) {
			fio_libaio_queued(td, io_us, ret);
			io_u_mark_submit(td, ret);
			ld->iocbs_nr -= ret;
			io_us += ret;
			iocbs += ret;
			ret = 0;
		} else if (!ret || ret == -EAGAIN || ret == -EINTR) {
			if (!ret)
				io_u_mark_submit(td, ret);
			continue;
		} else
			break;
	} while (ld->iocbs_nr);

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
	}
}

static int fio_libaio_init(struct thread_data *td)
{
	struct libaio_data *ld = malloc(sizeof(*ld));
	struct libaio_options *o = td->eo;
	int err = 0;

	memset(ld, 0, sizeof(*ld));

	/*
	 * First try passing in 0 for queue depth, since we don't
	 * care about the user ring. If that fails, the kernel is too old
	 * and we need the right depth.
	 */
	if (!o->userspace_reap)
		err = io_queue_init(INT_MAX, &ld->aio_ctx);
	if (o->userspace_reap || err == -EINVAL)
		err = io_queue_init(td->o.iodepth, &ld->aio_ctx);
	if (err) {
		td_verror(td, -err, "io_queue_init");
		log_err("fio: check /proc/sys/fs/aio-max-nr\n");
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
	.name			= "libaio",
	.version		= FIO_IOOPS_VERSION,
	.init			= fio_libaio_init,
	.prep			= fio_libaio_prep,
	.queue			= fio_libaio_queue,
	.commit			= fio_libaio_commit,
	.cancel			= fio_libaio_cancel,
	.getevents		= fio_libaio_getevents,
	.event			= fio_libaio_event,
	.cleanup		= fio_libaio_cleanup,
	.open_file		= generic_open_file,
	.close_file		= generic_close_file,
	.get_file_size		= generic_get_file_size,
	.options		= options,
	.option_struct_size	= sizeof(struct libaio_options),
};

static void fio_init fio_libaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
