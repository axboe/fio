/*
 * splice io engine
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>

#include "../fio.h"
#include "../os.h"

#ifdef FIO_HAVE_SPLICE

struct spliceio_data {
	struct io_u *last_io_u;
	int pipe[2];
};

static int fio_spliceio_getevents(struct thread_data *td, int fio_unused min,
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

static struct io_u *fio_spliceio_event(struct thread_data *td, int event)
{
	struct spliceio_data *sd = td->io_ops->data;

	assert(event == 0);

	return sd->last_io_u;
}

/*
 * For splice reading, we unfortunately cannot (yet) vmsplice the other way.
 * So just splice the data from the file into the pipe, and use regular
 * read to fill the buffer. Doesn't make a lot of sense, but...
 */
static int fio_splice_read(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops->data;
	struct fio_file *f = io_u->file;
	int ret, ret2, buflen;
	off_t offset;
	void *p;

	offset = io_u->offset;
	buflen = io_u->buflen;
	p = io_u->buf;
	while (buflen) {
		int this_len = buflen;

		if (this_len > SPLICE_DEF_SIZE)
			this_len = SPLICE_DEF_SIZE;

		ret = splice(f->fd, &offset, sd->pipe[1], NULL, this_len, SPLICE_F_MORE);
		if (ret < 0) {
			if (errno == ENODATA || errno == EAGAIN)
				continue;

			return errno;
		}

		buflen -= ret;

		while (ret) {
			ret2 = read(sd->pipe[0], p, ret);
			if (ret2 < 0)
				return errno;

			ret -= ret2;
			p += ret2;
		}
	}

	return io_u->buflen;
}

/*
 * For splice writing, we can vmsplice our data buffer directly into a
 * pipe and then splice that to a file.
 */
static int fio_splice_write(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops->data;
	struct iovec iov[1] = {
		{
			.iov_base = io_u->buf,
			.iov_len = io_u->buflen,
		}
	};
	struct pollfd pfd = { .fd = sd->pipe[1], .events = POLLOUT, };
	struct fio_file *f = io_u->file;
	off_t off = io_u->offset;
	int ret, ret2;

	while (iov[0].iov_len) {
		if (poll(&pfd, 1, -1) < 0)
			return errno;

		ret = vmsplice(sd->pipe[1], iov, 1, SPLICE_F_NONBLOCK);
		if (ret < 0)
			return errno;

		iov[0].iov_len -= ret;
		iov[0].iov_base += ret;

		while (ret) {
			ret2 = splice(sd->pipe[0], NULL, f->fd, &off, ret, 0);
			if (ret2 < 0)
				return errno;

			ret -= ret2;
		}
	}

	return io_u->buflen;
}

static int fio_spliceio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops->data;
	unsigned int ret;

	if (io_u->ddir == DDIR_READ)
		ret = fio_splice_read(td, io_u);
	else if (io_u->ddir == DDIR_WRITE)
		ret = fio_splice_write(td, io_u);
	else
		ret = fsync(io_u->file->fd);

	if (ret != io_u->buflen) {
		if (ret > 0) {
			io_u->resid = io_u->buflen - ret;
			io_u->error = ENODATA;
		} else
			io_u->error = errno;
	}

	if (!io_u->error)
		sd->last_io_u = io_u;

	return io_u->error;
}

static void fio_spliceio_cleanup(struct thread_data *td)
{
	struct spliceio_data *sd = td->io_ops->data;

	if (sd) {
		close(sd->pipe[0]);
		close(sd->pipe[1]);
		free(sd);
		td->io_ops->data = NULL;
	}
}

static int fio_spliceio_init(struct thread_data *td)
{
	struct spliceio_data *sd = malloc(sizeof(*sd));

	sd->last_io_u = NULL;
	if (pipe(sd->pipe) < 0) {
		td_verror(td, errno);
		free(sd);
		return 1;
	}

	td->io_ops->data = sd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "splice",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_spliceio_init,
	.queue		= fio_spliceio_queue,
	.getevents	= fio_spliceio_getevents,
	.event		= fio_spliceio_event,
	.cleanup	= fio_spliceio_cleanup,
	.flags		= FIO_SYNCIO,
};

#else /* FIO_HAVE_SPLICE */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_spliceio_init(struct thread_data fio_unused *td)
{
	fprintf(stderr, "fio: splice not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "splice",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_spliceio_init,
};

#endif

static void fio_init fio_spliceio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_spliceio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
