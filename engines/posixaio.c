/*
 * posix aio io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"
#include "../os.h"

#ifdef FIO_HAVE_POSIXAIO

struct posixaio_data {
	struct io_u **aio_events;
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

	if (r == 1 || r == AIO_CANCELED)
		return 0;

	return 1;
}

static int fio_posixaio_prep(struct thread_data fio_unused *td,
			     struct io_u *io_u)
{
	struct aiocb *aiocb = &io_u->aiocb;
	struct fio_file *f = io_u->file;

	aiocb->aio_fildes = f->fd;
	aiocb->aio_buf = io_u->buf;
	aiocb->aio_nbytes = io_u->buflen;
	aiocb->aio_offset = io_u->offset;

	io_u->seen = 0;
	return 0;
}

static int fio_posixaio_getevents(struct thread_data *td, int min, int max,
				  struct timespec *t)
{
	struct posixaio_data *pd = td->io_ops->data;
	struct list_head *entry;
	struct timespec start;
	int r, have_timeout = 0;

	if (t && !fill_timespec(&start))
		have_timeout = 1;

	r = 0;
restart:
	list_for_each(entry, &td->io_u_busylist) {
		struct io_u *io_u = list_entry(entry, struct io_u, list);
		int err;

		if (io_u->seen)
			continue;

		err = aio_error(&io_u->aiocb);
		switch (err) {
			default:
				io_u->error = err;
			case ECANCELED:
			case 0:
				pd->aio_events[r++] = io_u;
				io_u->seen = 1;
				break;
			case EINPROGRESS:
				break;
		}

		if (r >= max)
			break;
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
	 * hrmpf, we need to wait for more. we should use aio_suspend, for
	 * now just sleep a little and recheck status of busy-and-not-seen
	 */
	usleep(1000);
	goto restart;
}

static struct io_u *fio_posixaio_event(struct thread_data *td, int event)
{
	struct posixaio_data *pd = td->io_ops->data;

	return pd->aio_events[event];
}

static int fio_posixaio_queue(struct thread_data fio_unused *td,
			      struct io_u *io_u)
{
	struct aiocb *aiocb = &io_u->aiocb;
	int ret;

	if (io_u->ddir == DDIR_READ)
		ret = aio_read(aiocb);
	else if (io_u->ddir == DDIR_WRITE)
		ret = aio_write(aiocb);
	else
		ret = aio_fsync(O_SYNC, aiocb);

	if (ret)
		io_u->error = errno;
		
	return io_u->error;
}

static void fio_posixaio_cleanup(struct thread_data *td)
{
	struct posixaio_data *pd = td->io_ops->data;

	if (pd) {
		free(pd->aio_events);
		free(pd);
		td->io_ops->data = NULL;
	}
}

static int fio_posixaio_init(struct thread_data *td)
{
	struct posixaio_data *pd = malloc(sizeof(*pd));

	memset(pd, 0, sizeof(*pd));
	pd->aio_events = malloc(td->iodepth * sizeof(struct io_u *));
	memset(pd->aio_events, 0, td->iodepth * sizeof(struct io_u *));

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
};

#else /* FIO_HAVE_POSIXAIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_posixaio_init(struct thread_data fio_unused *td)
{
	fprintf(stderr, "fio: posixaio not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "posixaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_posixaio_init,
};

#endif

static void fio_init fio_posixaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_posixaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
