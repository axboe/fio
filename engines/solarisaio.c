/*
 * Native Solaris async IO engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include "../fio.h"

#ifdef FIO_HAVE_SOLARISAIO

#include <sys/asynch.h>

struct solarisaio_data {
	struct io_u **aio_events;
	unsigned int nr;
};

static int fio_solarisaio_cancel(struct thread_data fio_unused *td,
			       struct io_u *io_u)
{
	return aiocancel(&io_u->resultp);
}

static int fio_solarisaio_prep(struct thread_data fio_unused *td,
			    struct io_u *io_u)
{
	io_u->resultp.aio_return = AIO_INPROGRESS;
	return 0;
}

static int fio_solarisaio_getevents(struct thread_data *td, unsigned int min,
				    unsigned int max, struct timespec *t)
{
	struct solarisaio_data *sd = td->io_ops->data;
	struct timeval tv;
	unsigned int r;

	r = 0;
	do {
		struct io_u *io_u;
		aio_result_t *p;

		if (!min || !t) {
			tv.tv_sec = 0;
			tv.tv_usec = 0;
		} else {
			tv.tv_sec = t->tv_sec;
			tv.tv_usec = t->tv_nsec / 1000;
		}

		p = aiowait(&tv);
		if (p) {
			io_u = container_of(p, struct io_u, resultp);

			sd->aio_events[r++] = io_u;
			sd->nr--;

			if (io_u->resultp.aio_return >= 0) {
				io_u->resid = io_u->xfer_buflen
						- io_u->resultp.aio_return;
				io_u->error = 0;
			} else
				io_u->error = io_u->resultp.aio_return;
		}
	} while (r < min);

	return r;
}

static struct io_u *fio_solarisaio_event(struct thread_data *td, int event)
{
	struct solarisaio_data *sd = td->io_ops->data;

	return sd->aio_events[event];
}

static int fio_solarisaio_queue(struct thread_data fio_unused *td,
			      struct io_u *io_u)
{
	struct solarisaio_data *sd = td->io_ops->data;
	struct fio_file *f = io_u->file;
	off_t off;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_SYNC) {
		if (sd->nr)
			return FIO_Q_BUSY;
		if (fsync(f->fd) < 0)
			io_u->error = errno;

		return FIO_Q_COMPLETED;
	}

	if (sd->nr == td->o.iodepth)
		return FIO_Q_BUSY;

	off = io_u->offset;
	if (io_u->ddir == DDIR_READ)
		ret = aioread(f->fd, io_u->xfer_buf, io_u->xfer_buflen, off,
					SEEK_SET, &io_u->resultp);
	else
		ret = aiowrite(f->fd, io_u->xfer_buf, io_u->xfer_buflen, off,
					SEEK_SET, &io_u->resultp);
	if (ret) {
		io_u->error = errno;
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	sd->nr++;
	return FIO_Q_QUEUED;
}

static void fio_solarisaio_cleanup(struct thread_data *td)
{
	struct solarisaio_data *sd = td->io_ops->data;

	if (sd) {
		free(sd->aio_events);
		free(sd);
	}
}

static int fio_solarisaio_init(struct thread_data *td)
{
	struct solarisaio_data *sd = malloc(sizeof(*sd));

	memset(sd, 0, sizeof(*sd));
	sd->aio_events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(sd->aio_events, 0, td->o.iodepth * sizeof(struct io_u *));

	td->io_ops->data = sd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "solarisaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_solarisaio_init,
	.prep		= fio_solarisaio_prep,
	.queue		= fio_solarisaio_queue,
	.cancel		= fio_solarisaio_cancel,
	.getevents	= fio_solarisaio_getevents,
	.event		= fio_solarisaio_event,
	.cleanup	= fio_solarisaio_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
};

#else /* FIO_HAVE_SOLARISAIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_solarisaio_init(struct thread_data fio_unused *td)
{
	fprintf(stderr, "fio: solarisaio not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "solarisaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_solarisaio_init,
};

#endif

static void fio_init fio_solarisaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_solarisaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
