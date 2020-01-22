/*
 * libaio engine
 *
 * IO engine using the Linux native aio interface.
 *
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libaio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "../fio.h"
#include "../lib/pow2.h"
#include "../optgroup.h"
#include "../lib/memalign.h"

/* Should be defined in newest aio_abi.h */
#ifndef IOCB_FLAG_IOPRIO
#define IOCB_FLAG_IOPRIO    (1 << 1)
#endif

static int fio_libaio_commit(struct thread_data *td);
static int fio_libaio_init(struct thread_data *td);

struct libaio_data {
	io_context_t aio_ctx;
	struct io_event *aio_events;
	struct iocb **iocbs;
	struct io_u **io_us;

	struct io_u **io_u_index;

	/*
	 * Basic ring buffer. 'head' is incremented in _queue(), and
	 * 'tail' is incremented in _commit(). We keep 'queued' so
	 * that we know if the ring is full or empty, when
	 * 'head' == 'tail'. 'entries' is the ring size, and
	 * 'is_pow2' is just an optimization to use AND instead of
	 * modulus to get the remainder on ring increment.
	 */
	int is_pow2;
	unsigned int entries;
	unsigned int queued;
	unsigned int head;
	unsigned int tail;
};

struct libaio_options {
	void *pad;
	unsigned int userspace_reap;
	unsigned int cmdprio_percentage;
};

static struct fio_option options[] = {
	{
		.name	= "userspace_reap",
		.lname	= "Libaio userspace reaping",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct libaio_options, userspace_reap),
		.help	= "Use alternative user-space reap implementation",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
#ifdef FIO_HAVE_IOPRIO_CLASS
	{
		.name	= "cmdprio_percentage",
		.lname	= "high priority percentage",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct libaio_options, cmdprio_percentage),
		.minval	= 1,
		.maxval	= 100,
		.help	= "Send high priority I/O this percentage of the time",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBAIO,
	},
#else
	{
		.name	= "cmdprio_percentage",
		.lname	= "high priority percentage",
		.type	= FIO_OPT_UNSUPPORTED,
		.help	= "Your platform does not support I/O priority classes",
	},
#endif
	{
		.name	= NULL,
	},
};

static inline void ring_inc(struct libaio_data *ld, unsigned int *val,
			    unsigned int add)
{
	if (ld->is_pow2)
		*val = (*val + add) & (ld->entries - 1);
	else
		*val = (*val + add) % ld->entries;
}

static int fio_libaio_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct iocb *iocb = &io_u->iocb;

	if (io_u->ddir == DDIR_READ) {
		io_prep_pread(iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	} else if (io_u->ddir == DDIR_WRITE) {
		io_prep_pwrite(iocb, f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	} else if (ddir_sync(io_u->ddir))
		io_prep_fsync(iocb, f->fd);

	return 0;
}

static void fio_libaio_prio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_options *o = td->eo;
	if (rand_between(&td->prio_state, 0, 99) < o->cmdprio_percentage) {
		io_u->iocb.aio_reqprio = IOPRIO_CLASS_RT << IOPRIO_CLASS_SHIFT;
		io_u->iocb.u.c.flags |= IOCB_FLAG_IOPRIO;
		io_u->flags |= IO_U_F_PRIORITY;
	}
	return;
}

static struct io_u *fio_libaio_event(struct thread_data *td, int event)
{
	struct libaio_data *ld = td->io_ops_data;
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
				unsigned int max, const struct timespec *t)
{
	struct libaio_data *ld = td->io_ops_data;
	struct libaio_options *o = td->eo;
	unsigned actual_min = td->o.iodepth_batch_complete_min == 0 ? 0 : min;
	struct timespec __lt, *lt = NULL;
	int r, events = 0;

	if (t) {
		__lt = *t;
		lt = &__lt;
	}

	do {
		if (o->userspace_reap == 1
		    && actual_min == 0
		    && ((struct aio_ring *)(ld->aio_ctx))->magic
				== AIO_RING_MAGIC) {
			r = user_io_getevents(ld->aio_ctx, max,
				ld->aio_events + events);
		} else {
			r = io_getevents(ld->aio_ctx, actual_min,
				max, ld->aio_events + events, lt);
		}
		if (r > 0)
			events += r;
		else if ((min && r == 0) || r == -EAGAIN) {
			fio_libaio_commit(td);
			if (actual_min)
				usleep(10);
		} else if (r != -EINTR)
			break;
	} while (events < min);

	return r < 0 ? r : events;
}

static enum fio_q_status fio_libaio_queue(struct thread_data *td,
					  struct io_u *io_u)
{
	struct libaio_data *ld = td->io_ops_data;
	struct libaio_options *o = td->eo;

	fio_ro_check(td, io_u);

	if (ld->queued == td->o.iodepth)
		return FIO_Q_BUSY;

	/*
	 * fsync is tricky, since it can fail and we need to do it
	 * serialized with other io. the reason is that linux doesn't
	 * support aio fsync yet. So return busy for the case where we
	 * have pending io, to let fio complete those first.
	 */
	if (ddir_sync(io_u->ddir)) {
		if (ld->queued)
			return FIO_Q_BUSY;

		do_io_u_sync(td, io_u);
		return FIO_Q_COMPLETED;
	}

	if (io_u->ddir == DDIR_TRIM) {
		if (ld->queued)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);
		io_u_mark_submit(td, 1);
		io_u_mark_complete(td, 1);
		return FIO_Q_COMPLETED;
	}

	if (o->cmdprio_percentage)
		fio_libaio_prio_prep(td, io_u);

	ld->iocbs[ld->head] = &io_u->iocb;
	ld->io_us[ld->head] = io_u;
	ring_inc(ld, &ld->head, 1);
	ld->queued++;
	return FIO_Q_QUEUED;
}

static void fio_libaio_queued(struct thread_data *td, struct io_u **io_us,
			      unsigned int nr)
{
	struct timespec now;
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
	struct libaio_data *ld = td->io_ops_data;
	struct iocb **iocbs;
	struct io_u **io_us;
	struct timespec ts;
	int ret, wait_start = 0;

	if (!ld->queued)
		return 0;

	do {
		long nr = ld->queued;

		nr = min((unsigned int) nr, ld->entries - ld->tail);
		io_us = ld->io_us + ld->tail;
		iocbs = ld->iocbs + ld->tail;

		ret = io_submit(ld->aio_ctx, nr, iocbs);
		if (ret > 0) {
			fio_libaio_queued(td, io_us, ret);
			io_u_mark_submit(td, ret);

			ld->queued -= ret;
			ring_inc(ld, &ld->tail, ret);
			ret = 0;
			wait_start = 0;
		} else if (ret == -EINTR || !ret) {
			if (!ret)
				io_u_mark_submit(td, ret);
			wait_start = 0;
			continue;
		} else if (ret == -EAGAIN) {
			/*
			 * If we get EAGAIN, we should break out without
			 * error and let the upper layer reap some
			 * events for us. If we have no queued IO, we
			 * must loop here. If we loop for more than 30s,
			 * just error out, something must be buggy in the
			 * IO path.
			 */
			if (ld->queued) {
				ret = 0;
				break;
			}
			if (!wait_start) {
				fio_gettime(&ts, NULL);
				wait_start = 1;
			} else if (mtime_since_now(&ts) > 30000) {
				log_err("fio: aio appears to be stalled, giving up\n");
				break;
			}
			usleep(1);
			continue;
		} else if (ret == -ENOMEM) {
			/*
			 * If we get -ENOMEM, reap events if we can. If
			 * we cannot, treat it as a fatal event since there's
			 * nothing we can do about it.
			 */
			if (ld->queued)
				ret = 0;
			break;
		} else
			break;
	} while (ld->queued);

	return ret;
}

static int fio_libaio_cancel(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_ops_data;

	return io_cancel(ld->aio_ctx, &io_u->iocb, ld->aio_events);
}

static void fio_libaio_cleanup(struct thread_data *td)
{
	struct libaio_data *ld = td->io_ops_data;

	if (ld) {
		/*
		 * Work-around to avoid huge RCU stalls at exit time. If we
		 * don't do this here, then it'll be torn down by exit_aio().
		 * But for that case we can parallellize the freeing, thus
		 * speeding it up a lot.
		 */
		if (!(td->flags & TD_F_CHILD))
			io_destroy(ld->aio_ctx);
		free(ld->aio_events);
		free(ld->iocbs);
		free(ld->io_us);
		free(ld);
	}
}

static int fio_libaio_post_init(struct thread_data *td)
{
	struct libaio_data *ld = td->io_ops_data;
	int err;

	err = io_queue_init(td->o.iodepth, &ld->aio_ctx);
	if (err) {
		td_verror(td, -err, "io_queue_init");
		return 1;
	}

	return 0;
}

static int fio_libaio_init(struct thread_data *td)
{
	struct libaio_data *ld;
	struct thread_options *to = &td->o;
	struct libaio_options *o = td->eo;

	ld = calloc(1, sizeof(*ld));

	ld->entries = td->o.iodepth;
	ld->is_pow2 = is_power_of_2(ld->entries);
	ld->aio_events = calloc(ld->entries, sizeof(struct io_event));
	ld->iocbs = calloc(ld->entries, sizeof(struct iocb *));
	ld->io_us = calloc(ld->entries, sizeof(struct io_u *));

	td->io_ops_data = ld;
	/*
	 * Check for option conflicts
	 */
	if ((fio_option_is_set(to, ioprio) || fio_option_is_set(to, ioprio_class)) &&
			o->cmdprio_percentage != 0) {
		log_err("%s: cmdprio_percentage option and mutually exclusive "
				"prio or prioclass option is set, exiting\n", to->name);
		td_verror(td, EINVAL, "fio_libaio_init");
		return 1;
	}
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "libaio",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_ASYNCIO_SYNC_TRIM,
	.init			= fio_libaio_init,
	.post_init		= fio_libaio_post_init,
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
