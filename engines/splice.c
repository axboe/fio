/*
 * splice engine
 *
 * IO engine that transfers data by doing splices to/from pipes and
 * the files.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>
#include <sys/mman.h>

#include "../fio.h"

struct spliceio_data {
	int pipe[2];
	int vmsplice_to_user;
	int vmsplice_to_user_map;
};

/*
 * vmsplice didn't use to support splicing to user space, this is the old
 * variant of getting that job done. Doesn't make a lot of sense, but it
 * uses splices to move data from the source into a pipe.
 */
static int fio_splice_read_old(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops_data;
	struct fio_file *f = io_u->file;
	int ret, ret2, buflen;
	off_t offset;
	void *p;

	offset = io_u->offset;
	buflen = io_u->xfer_buflen;
	p = io_u->xfer_buf;
	while (buflen) {
		int this_len = buflen;

		if (this_len > SPLICE_DEF_SIZE)
			this_len = SPLICE_DEF_SIZE;

		ret = splice(f->fd, &offset, sd->pipe[1], NULL, this_len, SPLICE_F_MORE);
		if (ret < 0) {
			if (errno == ENODATA || errno == EAGAIN)
				continue;

			return -errno;
		}

		buflen -= ret;

		while (ret) {
			ret2 = read(sd->pipe[0], p, ret);
			if (ret2 < 0)
				return -errno;

			ret -= ret2;
			p += ret2;
		}
	}

	return io_u->xfer_buflen;
}

/*
 * We can now vmsplice into userspace, so do the transfer by splicing into
 * a pipe and vmsplicing that into userspace.
 */
static int fio_splice_read(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops_data;
	struct fio_file *f = io_u->file;
	struct iovec iov;
	int ret , buflen, mmap_len;
	off_t offset;
	void *p, *map;

	ret = 0;
	offset = io_u->offset;
	mmap_len = buflen = io_u->xfer_buflen;

	if (sd->vmsplice_to_user_map) {
		map = mmap(io_u->xfer_buf, buflen, PROT_READ, MAP_PRIVATE|OS_MAP_ANON, 0, 0);
		if (map == MAP_FAILED) {
			td_verror(td, errno, "mmap io_u");
			return -1;
		}

		p = map;
	} else {
		map = NULL;
		p = io_u->xfer_buf;
	}

	while (buflen) {
		int this_len = buflen;
		int flags = 0;

		if (this_len > SPLICE_DEF_SIZE) {
			this_len = SPLICE_DEF_SIZE;
			flags = SPLICE_F_MORE;
		}

		ret = splice(f->fd, &offset, sd->pipe[1], NULL, this_len,flags);
		if (ret < 0) {
			if (errno == ENODATA || errno == EAGAIN)
				continue;

			td_verror(td, errno, "splice-from-fd");
			break;
		}

		buflen -= ret;
		iov.iov_base = p;
		iov.iov_len = ret;

		while (iov.iov_len) {
			ret = vmsplice(sd->pipe[0], &iov, 1, SPLICE_F_MOVE);
			if (ret < 0) {
				if (errno == EFAULT &&
				    sd->vmsplice_to_user_map) {
					sd->vmsplice_to_user_map = 0;
					munmap(map, mmap_len);
					map = NULL;
					p = io_u->xfer_buf;
					iov.iov_base = p;
					continue;
				}
				if (errno == EBADF) {
					ret = -EBADF;
					break;
				}
				td_verror(td, errno, "vmsplice");
				break;
			} else if (!ret) {
				td_verror(td, ENODATA, "vmsplice");
				ret = -1;
				break;
			}

			iov.iov_len -= ret;
			iov.iov_base += ret;
			p += ret;
		}
		if (ret < 0)
			break;
	}

	if (sd->vmsplice_to_user_map && munmap(map, mmap_len) < 0) {
		td_verror(td, errno, "munnap io_u");
		return -1;
	}
	if (ret < 0)
		return ret;

	return io_u->xfer_buflen;
}

/*
 * For splice writing, we can vmsplice our data buffer directly into a
 * pipe and then splice that to a file.
 */
static int fio_splice_write(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops_data;
	struct iovec iov = {
		.iov_base = io_u->xfer_buf,
		.iov_len = io_u->xfer_buflen,
	};
	struct pollfd pfd = { .fd = sd->pipe[1], .events = POLLOUT, };
	struct fio_file *f = io_u->file;
	off_t off = io_u->offset;
	int ret, ret2;

	while (iov.iov_len) {
		if (poll(&pfd, 1, -1) < 0)
			return errno;

		ret = vmsplice(sd->pipe[1], &iov, 1, SPLICE_F_NONBLOCK);
		if (ret < 0)
			return -errno;

		iov.iov_len -= ret;
		iov.iov_base += ret;

		while (ret) {
			ret2 = splice(sd->pipe[0], NULL, f->fd, &off, ret, 0);
			if (ret2 < 0)
				return -errno;

			ret -= ret2;
		}
	}

	return io_u->xfer_buflen;
}

static int fio_spliceio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct spliceio_data *sd = td->io_ops_data;
	int ret = 0;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ) {
		if (sd->vmsplice_to_user) {
			ret = fio_splice_read(td, io_u);
			/*
			 * This kernel doesn't support vmsplice to user
			 * space. Reset the vmsplice_to_user flag, so that
			 * we retry below and don't hit this path again.
			 */
			if (ret == -EBADF)
				sd->vmsplice_to_user = 0;
		}
		if (!sd->vmsplice_to_user)
			ret = fio_splice_read_old(td, io_u);
	} else if (io_u->ddir == DDIR_WRITE)
		ret = fio_splice_write(td, io_u);
	else if (io_u->ddir == DDIR_TRIM)
		ret = do_io_u_trim(td, io_u);
	else
		ret = do_io_u_sync(td, io_u);

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		if (io_u->error == EINVAL)
			log_err("fio: looks like splice doesn't work on this"
					" file system\n");
	}

	return FIO_Q_COMPLETED;
}

static void fio_spliceio_cleanup(struct thread_data *td)
{
	struct spliceio_data *sd = td->io_ops_data;

	if (sd) {
		close(sd->pipe[0]);
		close(sd->pipe[1]);
		free(sd);
	}
}

static int fio_spliceio_init(struct thread_data *td)
{
	struct spliceio_data *sd = malloc(sizeof(*sd));

	if (pipe(sd->pipe) < 0) {
		td_verror(td, errno, "pipe");
		free(sd);
		return 1;
	}

	/*
	 * Assume this work, we'll reset this if it doesn't
	 */
	sd->vmsplice_to_user = 1;

	/*
	 * Works with "real" vmsplice to user, eg mapping pages directly.
	 * Reset if we fail.
	 */
	sd->vmsplice_to_user_map = 1;

	/*
	 * And if vmsplice_to_user works, we definitely need aligned
	 * buffers. Just set ->odirect to force that.
	 */
	if (td_read(td))
		td->o.mem_align = 1;

	td->io_ops_data = sd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "splice",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_spliceio_init,
	.queue		= fio_spliceio_queue,
	.cleanup	= fio_spliceio_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO | FIO_PIPEIO,
};

static void fio_init fio_spliceio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_spliceio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
