/*
 * binject engine
 *
 * IO engine that uses the Linux binject interface to directly inject
 * bio's to block devices.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "../fio.h"

#ifdef FIO_HAVE_BINJECT

struct binject_data {
	struct b_user_cmd *cmds;
	struct io_u **events;
	struct pollfd *pfds;
	int *fd_flags;
};

struct binject_file {
	unsigned int bs;
	int minor;
	int fd;
};

static void binject_buc_init(struct binject_data *bd, struct io_u *io_u)
{
	struct b_user_cmd *buc = &io_u->buc;

	memset(buc, 0, sizeof(*buc));
	binject_buc_set_magic(buc);

	buc->buf = (unsigned long) io_u->xfer_buf;
	buc->len = io_u->xfer_buflen;
	buc->offset = io_u->offset;
	buc->usr_ptr = (unsigned long) io_u;

	buc->flags = B_FLAG_NOIDLE | B_FLAG_UNPLUG;
	assert(buc->buf);
}

static int pollin_events(struct pollfd *pfds, int fds)
{
	int i;

	for (i = 0; i < fds; i++)
		if (pfds[i].revents & POLLIN)
			return 1;

	return 0;
}

static unsigned int binject_read_commands(struct thread_data *td, void *p,
					  int left, int *err)
{
	struct binject_file *bf;
	struct fio_file *f;
	int i, ret, events;

one_more:
	events = 0;
	for_each_file(td, f, i) {
		bf = (struct binject_file *) (uintptr_t) f->engine_data;
		ret = read(bf->fd, p, left * sizeof(struct b_user_cmd));
		if (ret < 0) {
			if (errno == EAGAIN)
				continue;
			*err = -errno;
			td_verror(td, errno, "read");
			break;
		} else if (ret) {
			p += ret;
			events += ret / sizeof(struct b_user_cmd);
		}
	}

	if (*err || events)
		return events;

	usleep(1000);
	goto one_more;
}

static int fio_binject_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max, struct timespec fio_unused *t)
{
	struct binject_data *bd = td->io_ops->data;
	int left = max, ret, r = 0, ev_index = 0;
	void *buf = bd->cmds;
	unsigned int i, events;
	struct fio_file *f;
	struct binject_file *bf;

	/*
	 * Fill in the file descriptors
	 */
	for_each_file(td, f, i) {
		bf = (struct binject_file *) (uintptr_t) f->engine_data;

		/*
		 * don't block for min events == 0
		 */
		if (!min)
			bd->fd_flags[i] = fio_set_fd_nonblocking(bf->fd, "binject");
		else
			bd->fd_flags[i] = -1;

		bd->pfds[i].fd = bf->fd;
		bd->pfds[i].events = POLLIN;
	}

	while (left) {
		while (!min) {
			ret = poll(bd->pfds, td->o.nr_files, -1);
			if (ret < 0) {
				if (!r)
					r = -errno;
				td_verror(td, errno, "poll");
				break;
			} else if (!ret)
				continue;

			if (pollin_events(bd->pfds, td->o.nr_files))
				break;
		}

		if (r < 0)
			break;

		events = binject_read_commands(td, buf, left, &r);

		if (r < 0)
			break;

		left -= events;
		r += events;

		for (i = 0; i < events; i++) {
			struct b_user_cmd *buc = (struct b_user_cmd *) buf + i;

			bd->events[ev_index] = (struct io_u *) (unsigned long) buc->usr_ptr;
			ev_index++;
		}
	}

	if (!min) {
		for_each_file(td, f, i) {
			bf = (struct binject_file *) (uintptr_t) f->engine_data;

			if (bd->fd_flags[i] == -1)
				continue;

			if (fcntl(bf->fd, F_SETFL, bd->fd_flags[i]) < 0)
				log_err("fio: binject failed to restore fcntl flags: %s\n", strerror(errno));
		}
	}

	if (r > 0)
		assert(ev_index == r);

	return r;
}

static int fio_binject_doio(struct thread_data *td, struct io_u *io_u)
{
	struct b_user_cmd *buc = &io_u->buc;
	struct binject_file *bf = (struct binject_file *) (uintptr_t) io_u->file->engine_data;
	int ret;

	ret = write(bf->fd, buc, sizeof(*buc));
	if (ret < 0)
		return ret;

	return FIO_Q_QUEUED;
}

static int fio_binject_prep(struct thread_data *td, struct io_u *io_u)
{
	struct binject_data *bd = td->io_ops->data;
	struct b_user_cmd *buc = &io_u->buc;
	struct binject_file *bf = (struct binject_file *) (uintptr_t) io_u->file->engine_data;

	if (io_u->xfer_buflen & (bf->bs - 1)) {
		log_err("read/write not sector aligned\n");
		return EINVAL;
	}

	if (io_u->ddir == DDIR_READ) {
		binject_buc_init(bd, io_u);
		buc->type = B_TYPE_READ;
	} else if (io_u->ddir == DDIR_WRITE) {
		binject_buc_init(bd, io_u);
		if (io_u->flags & IO_U_F_BARRIER)
			buc->type = B_TYPE_WRITEBARRIER;
		else
			buc->type = B_TYPE_WRITE;
	} else if (io_u->ddir == DDIR_TRIM) {
		binject_buc_init(bd, io_u);
		buc->type = B_TYPE_DISCARD;
	} else {
		assert(0);
	}

	return 0;
}

static int fio_binject_queue(struct thread_data *td, struct io_u *io_u)
{
	int ret;

	fio_ro_check(td, io_u);

	ret = fio_binject_doio(td, io_u);

	if (ret < 0)
		io_u->error = errno;

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	return ret;
}

static struct io_u *fio_binject_event(struct thread_data *td, int event)
{
	struct binject_data *bd = td->io_ops->data;

	return bd->events[event];
}

static int binject_open_ctl(struct thread_data *td)
{
	int fd;

	fd = open("/dev/binject-ctl", O_RDWR);
	if (fd < 0)
		td_verror(td, errno, "open binject-ctl");

	return fd;
}

static void binject_unmap_dev(struct thread_data *td, struct binject_file *bf)
{
	struct b_ioctl_cmd bic;
	int fdb;

	if (bf->fd >= 0) {
		close(bf->fd);
		bf->fd = -1;
	}

	fdb = binject_open_ctl(td);
	if (fdb < 0)
		return;

	bic.minor = bf->minor;

	if (ioctl(fdb, B_IOCTL_DEL, &bic) < 0)
		td_verror(td, errno, "binject dev unmap");

	close(fdb);
}

static int binject_map_dev(struct thread_data *td, struct binject_file *bf,
			   int fd)
{
	struct b_ioctl_cmd bic;
	char name[80];
	struct stat sb;
	int fdb, dev_there, loops;

	fdb = binject_open_ctl(td);
	if (fdb < 0)
		return 1;

	bic.fd = fd;

	if (ioctl(fdb, B_IOCTL_ADD, &bic) < 0) {
		td_verror(td, errno, "binject dev map");
		close(fdb);
		return 1;
	}

	bf->minor = bic.minor;

	sprintf(name, "/dev/binject%u", bf->minor);

	/*
	 * Wait for udev to create the node...
	 */
	dev_there = loops = 0;
	do {
		if (!stat(name, &sb)) {
			dev_there = 1;
			break;
		}

		usleep(10000);
	} while (++loops < 100);

	close(fdb);

	if (!dev_there) {
		log_err("fio: timed out waiting for binject dev\n");
		goto err_unmap;
	}

	bf->fd = open(name, O_RDWR);
	if (bf->fd < 0) {
		td_verror(td, errno, "binject dev open");
err_unmap:
		binject_unmap_dev(td, bf);
		return 1;
	}

	return 0;
}

static int fio_binject_close_file(struct thread_data *td, struct fio_file *f)
{
	struct binject_file *bf = (struct binject_file *) (uintptr_t) f->engine_data;

	if (bf) {
		binject_unmap_dev(td, bf);
		free(bf);
		f->engine_data = 0;
		return generic_close_file(td, f);
	}

	return 0;
}

static int fio_binject_open_file(struct thread_data *td, struct fio_file *f)
{
	struct binject_file *bf;
	unsigned int bs;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return 1;

	if (f->filetype != FIO_TYPE_BD) {
		log_err("fio: binject only works with block devices\n");
		goto err_close;
	}
	if (ioctl(f->fd, BLKSSZGET, &bs) < 0) {
		td_verror(td, errno, "BLKSSZGET");
		goto err_close;
	}

	bf = malloc(sizeof(*bf));
	bf->bs = bs;
	bf->minor = bf->fd = -1;
	f->engine_data = (uintptr_t) bf;

	if (binject_map_dev(td, bf, f->fd)) {
err_close:
		ret = generic_close_file(td, f);
		return 1;
	}

	return 0;
}

static void fio_binject_cleanup(struct thread_data *td)
{
	struct binject_data *bd = td->io_ops->data;

	if (bd) {
		free(bd->events);
		free(bd->cmds);
		free(bd->fd_flags);
		free(bd->pfds);
		free(bd);
	}
}

static int fio_binject_init(struct thread_data *td)
{
	struct binject_data *bd;

	bd = malloc(sizeof(*bd));
	memset(bd, 0, sizeof(*bd));

	bd->cmds = malloc(td->o.iodepth * sizeof(struct b_user_cmd));
	memset(bd->cmds, 0, td->o.iodepth * sizeof(struct b_user_cmd));

	bd->events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(bd->events, 0, td->o.iodepth * sizeof(struct io_u *));

	bd->pfds = malloc(sizeof(struct pollfd) * td->o.nr_files);
	memset(bd->pfds, 0, sizeof(struct pollfd) * td->o.nr_files);

	bd->fd_flags = malloc(sizeof(int) * td->o.nr_files);
	memset(bd->fd_flags, 0, sizeof(int) * td->o.nr_files);

	td->io_ops->data = bd;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "binject",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_binject_init,
	.prep		= fio_binject_prep,
	.queue		= fio_binject_queue,
	.getevents	= fio_binject_getevents,
	.event		= fio_binject_event,
	.cleanup	= fio_binject_cleanup,
	.open_file	= fio_binject_open_file,
	.close_file	= fio_binject_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_RAWIO | FIO_BARRIER | FIO_MEMALIGN,
};

#else /* FIO_HAVE_BINJECT */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_binject_init(struct thread_data fio_unused *td)
{
	log_err("fio: ioengine binject not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "binject",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_binject_init,
};

#endif

static void fio_init fio_binject_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_binject_unregister(void)
{
	unregister_ioengine(&ioengine);
}
