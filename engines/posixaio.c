/*
 * posixaio engine
 *
 * IO engine that uses the posix defined aio interface.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "../fio.h"

struct posixaio_data {
	struct io_u **aio_events;
	unsigned int queued;
};

static int fill_timespec(struct timespec *ts)
{
#ifdef _POSIX_TIMERS
	if (!clock_gettime(CLOCK_MONOTONIC, ts))
		return 0;

	perror("clock_gettime");
#endif
	return 1;
}

static unsigned long long ts_utime_since_now(struct timespec *t)
{
	long long sec, nsec;
	struct timespec now;

	if (fill_timespec(&now))
		return 0;
	
	sec = now.tv_sec - t->tv_sec;
	nsec = now.tv_nsec - t->tv_nsec;
	if (sec > 0 && nsec < 0) {
		sec--;
		nsec += 1000000000;
	}

	sec *= 1000000;
	nsec /= 1000;
	return sec + nsec;
}

static int fio_posixaio_cancel(struct thread_data fio_unused *td,
			       struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int r = aio_cancel(f->fd, &io_u->aiocb);

	if (r == AIO_ALLDONE || r == AIO_CANCELED)
		return 0;

	return 1;
}

static int fio_posixaio_prep(struct thread_data fio_unused *td,
			     struct io_u *io_u)
{
	os_aiocb_t *aiocb = &io_u->aiocb;
	struct fio_file *f = io_u->file;

	aiocb->aio_fildes = f->fd;
	aiocb->aio_buf = io_u->xfer_buf;
	aiocb->aio_nbytes = io_u->xfer_buflen;
	aiocb->aio_offset = io_u->offset;
	aiocb->aio_sigevent.sigev_notify = SIGEV_NONE;

	io_u->seen = 0;
	return 0;
}

#define SUSPEND_ENTRIES	8

static int fio_posixaio_getevents(struct thread_data *td, unsigned int min,
				  unsigned int max, struct timespec *t)
{
	struct posixaio_data *pd = td->io_ops->data;
	os_aiocb_t *suspend_list[SUSPEND_ENTRIES];
	struct flist_head *entry;
	struct timespec start;
	int have_timeout = 0;
	int suspend_entries = 0;
	unsigned int r;

	if (t && !fill_timespec(&start))
		have_timeout = 1;

	r = 0;
	memset(suspend_list, 0, sizeof(*suspend_list));
restart:
	flist_for_each(entry, &td->io_u_busylist) {
		struct io_u *io_u = flist_entry(entry, struct io_u, list);
		int err;

		if (io_u->seen)
			continue;

		err = aio_error(&io_u->aiocb);
		if (err == EINPROGRESS) {
			if (suspend_entries < SUSPEND_ENTRIES) {
				suspend_list[suspend_entries] = &io_u->aiocb;
				suspend_entries++;
			}
			continue;
		}

		io_u->seen = 1;
		pd->queued--;
		pd->aio_events[r++] = io_u;

		if (err == ECANCELED)
			io_u->resid = io_u->xfer_buflen;
		else if (!err) {
			ssize_t retval = aio_return(&io_u->aiocb);

			io_u->resid = io_u->xfer_buflen - retval;
		} else
			io_u->error = err;
	}

	if (r >= min)
		return r;

	if (have_timeout) {
		unsigned long long usec;

		usec = (t->tv_sec * 1000000) + (t->tv_nsec / 1000);
		if (ts_utime_since_now(&start) > usec)
			return r;
	}

	/*
	 * must have some in-flight, wait for at least one
	 */
	aio_suspend((const os_aiocb_t * const *)suspend_list,
							suspend_entries, t);
	goto restart;
}

static struct io_u *fio_posixaio_event(struct thread_data *td, int event)
{
	struct posixaio_data *pd = td->io_ops->data;

	return pd->aio_events[event];
}

static int fio_posixaio_queue(struct thread_data *td,
			      struct io_u *io_u)
{
	struct posixaio_data *pd = td->io_ops->data;
	os_aiocb_t *aiocb = &io_u->aiocb;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = aio_read(aiocb);
	else if (io_u->ddir == DDIR_WRITE)
		ret = aio_write(aiocb);
	else if (io_u->ddir == DDIR_TRIM) {
		if (pd->queued)
			return FIO_Q_BUSY;

		do_io_u_trim(td, io_u);
		return FIO_Q_COMPLETED;
	} else {
#ifdef CONFIG_POSIXAIO_FSYNC
		ret = aio_fsync(O_SYNC, aiocb);
#else
		if (pd->queued)
			return FIO_Q_BUSY;

		do_io_u_sync(td, io_u);
		return FIO_Q_COMPLETED;
#endif
	}
		
	if (ret) {
		/*
		 * At least OSX has a very low limit on the number of pending
		 * IOs, so if it returns EAGAIN, we are out of resources
		 * to queue more. Just return FIO_Q_BUSY to naturally
		 * drop off at this depth.
		 */
		if (errno == EAGAIN)
			return FIO_Q_BUSY;

		io_u->error = errno;
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	pd->queued++;
	return FIO_Q_QUEUED;
}

static void fio_posixaio_cleanup(struct thread_data *td)
{
	struct posixaio_data *pd = td->io_ops->data;

	if (pd) {
		free(pd->aio_events);
		free(pd);
	}
}

static int fio_posixaio_init(struct thread_data *td)
{
	struct posixaio_data *pd = malloc(sizeof(*pd));

	memset(pd, 0, sizeof(*pd));
	pd->aio_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(pd->aio_events, 0, td->o.iodepth * sizeof(struct io_u *));

	td->io_ops->data = pd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "posixaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_posixaio_init,
	.prep		= fio_posixaio_prep,
	.queue		= fio_posixaio_queue,
	.cancel		= fio_posixaio_cancel,
	.getevents	= fio_posixaio_getevents,
	.event		= fio_posixaio_event,
	.cleanup	= fio_posixaio_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
};

static void fio_init fio_posixaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_posixaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
