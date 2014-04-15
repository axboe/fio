/*
 * sg engine
 *
 * IO engine that uses the Linux SG v3 interface to talk to SCSI devices
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/poll.h>

#include "../fio.h"

#ifdef FIO_HAVE_SGIO

struct sgio_cmd {
	unsigned char cdb[10];
	int nr;
};

struct sgio_data {
	struct sgio_cmd *cmds;
	struct io_u **events;
	struct pollfd *pfds;
	int *fd_flags;
	void *sgbuf;
	unsigned int bs;
	int type_checked;
};

static void sgio_hdr_init(struct sgio_data *sd, struct sg_io_hdr *hdr,
			  struct io_u *io_u, int fs)
{
	struct sgio_cmd *sc = &sd->cmds[io_u->index];

	memset(hdr, 0, sizeof(*hdr));
	memset(sc->cdb, 0, sizeof(sc->cdb));

	hdr->interface_id = 'S';
	hdr->cmdp = sc->cdb;
	hdr->cmd_len = sizeof(sc->cdb);
	hdr->pack_id = io_u->index;
	hdr->usr_ptr = io_u;

	if (fs) {
		hdr->dxferp = io_u->xfer_buf;
		hdr->dxfer_len = io_u->xfer_buflen;
	}
}

static int pollin_events(struct pollfd *pfds, int fds)
{
	int i;

	for (i = 0; i < fds; i++)
		if (pfds[i].revents & POLLIN)
			return 1;

	return 0;
}

static int fio_sgio_getevents(struct thread_data *td, unsigned int min,
			      unsigned int max, struct timespec fio_unused *t)
{
	struct sgio_data *sd = td->io_ops->data;
	int left = max, ret, r = 0;
	void *buf = sd->sgbuf;
	unsigned int i, events;
	struct fio_file *f;

	/*
	 * Fill in the file descriptors
	 */
	for_each_file(td, f, i) {
		/*
		 * don't block for min events == 0
		 */
		if (!min)
			sd->fd_flags[i] = fio_set_fd_nonblocking(f->fd, "sg");
		else
			sd->fd_flags[i] = -1;

		sd->pfds[i].fd = f->fd;
		sd->pfds[i].events = POLLIN;
	}

	while (left) {
		void *p;

		do {
			if (!min)
				break;

			ret = poll(sd->pfds, td->o.nr_files, -1);
			if (ret < 0) {
				if (!r)
					r = -errno;
				td_verror(td, errno, "poll");
				break;
			} else if (!ret)
				continue;

			if (pollin_events(sd->pfds, td->o.nr_files))
				break;
		} while (1);

		if (r < 0)
			break;

re_read:
		p = buf;
		events = 0;
		for_each_file(td, f, i) {
			ret = read(f->fd, p, left * sizeof(struct sg_io_hdr));
			if (ret < 0) {
				if (errno == EAGAIN)
					continue;
				r = -errno;
				td_verror(td, errno, "read");
				break;
			} else if (ret) {
				p += ret;
				events += ret / sizeof(struct sg_io_hdr);
			}
		}

		if (r < 0)
			break;
		if (!events) {
			usleep(1000);
			goto re_read;
		}

		left -= events;
		r += events;

		for (i = 0; i < events; i++) {
			struct sg_io_hdr *hdr = (struct sg_io_hdr *) buf + i;

			sd->events[i] = hdr->usr_ptr;
		}
	}

	if (!min) {
		for_each_file(td, f, i) {
			if (sd->fd_flags[i] == -1)
				continue;

			if (fcntl(f->fd, F_SETFL, sd->fd_flags[i]) < 0)
				log_err("fio: sg failed to restore fcntl flags: %s\n", strerror(errno));
		}
	}

	return r;
}

static int fio_sgio_ioctl_doio(struct thread_data *td,
			       struct fio_file *f, struct io_u *io_u)
{
	struct sgio_data *sd = td->io_ops->data;
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	sd->events[0] = io_u;

	ret = ioctl(f->fd, SG_IO, hdr);
	if (ret < 0)
		return ret;

	return FIO_Q_COMPLETED;
}

static int fio_sgio_rw_doio(struct fio_file *f, struct io_u *io_u, int do_sync)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	ret = write(f->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return ret;

	if (do_sync) {
		ret = read(f->fd, hdr, sizeof(*hdr));
		if (ret < 0)
			return ret;
		return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;
}

static int fio_sgio_doio(struct thread_data *td, struct io_u *io_u, int do_sync)
{
	struct fio_file *f = io_u->file;

	if (f->filetype == FIO_TYPE_BD)
		return fio_sgio_ioctl_doio(td, f, io_u);

	return fio_sgio_rw_doio(f, io_u, do_sync);
}

static int fio_sgio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_ops->data;
	int nr_blocks, lba;

	if (io_u->xfer_buflen & (sd->bs - 1)) {
		log_err("read/write not sector aligned\n");
		return EINVAL;
	}

	if (io_u->ddir == DDIR_READ) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_FROM_DEV;
		hdr->cmdp[0] = 0x28;
	} else if (io_u->ddir == DDIR_WRITE) {
		sgio_hdr_init(sd, hdr, io_u, 1);

		hdr->dxfer_direction = SG_DXFER_TO_DEV;
		hdr->cmdp[0] = 0x2a;
	} else {
		sgio_hdr_init(sd, hdr, io_u, 0);

		hdr->dxfer_direction = SG_DXFER_NONE;
		hdr->cmdp[0] = 0x35;
	}

	if (hdr->dxfer_direction != SG_DXFER_NONE) {
		nr_blocks = io_u->xfer_buflen / sd->bs;
		lba = io_u->offset / sd->bs;
		hdr->cmdp[2] = (unsigned char) ((lba >> 24) & 0xff);
		hdr->cmdp[3] = (unsigned char) ((lba >> 16) & 0xff);
		hdr->cmdp[4] = (unsigned char) ((lba >>  8) & 0xff);
		hdr->cmdp[5] = (unsigned char) (lba & 0xff);
		hdr->cmdp[7] = (unsigned char) ((nr_blocks >> 8) & 0xff);
		hdr->cmdp[8] = (unsigned char) (nr_blocks & 0xff);
	}

	return 0;
}

static int fio_sgio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret, do_sync = 0;

	fio_ro_check(td, io_u);

	if (td->o.sync_io || td->o.odirect || ddir_sync(io_u->ddir))
		do_sync = 1;

	ret = fio_sgio_doio(td, io_u, do_sync);

	if (ret < 0)
		io_u->error = errno;
	else if (hdr->status) {
		io_u->resid = hdr->resid;
		io_u->error = EIO;
	}

	if (io_u->error) {
		td_verror(td, io_u->error, "xfer");
		return FIO_Q_COMPLETED;
	}

	return ret;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_ops->data;

	return sd->events[event];
}

static int fio_sgio_get_bs(struct thread_data *td, unsigned int *bs)
{
	struct sgio_data *sd = td->io_ops->data;
	struct io_u io_u;
	struct sg_io_hdr *hdr;
	unsigned char buf[8];
	int ret;

	memset(&io_u, 0, sizeof(io_u));
	io_u.file = td->files[0];

	hdr = &io_u.hdr;
	sgio_hdr_init(sd, hdr, &io_u, 0);
	memset(buf, 0, sizeof(buf));

	hdr->cmdp[0] = 0x25;
	hdr->dxfer_direction = SG_DXFER_FROM_DEV;
	hdr->dxferp = buf;
	hdr->dxfer_len = sizeof(buf);

	ret = fio_sgio_doio(td, &io_u, 1);
	if (ret)
		return ret;

	*bs = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	return 0;
}

static void fio_sgio_cleanup(struct thread_data *td)
{
	struct sgio_data *sd = td->io_ops->data;

	if (sd) {
		free(sd->events);
		free(sd->cmds);
		free(sd->fd_flags);
		free(sd->pfds);
		free(sd->sgbuf);
		free(sd);
	}
}

static int fio_sgio_init(struct thread_data *td)
{
	struct sgio_data *sd;

	sd = malloc(sizeof(*sd));
	memset(sd, 0, sizeof(*sd));
	sd->cmds = malloc(td->o.iodepth * sizeof(struct sgio_cmd));
	memset(sd->cmds, 0, td->o.iodepth * sizeof(struct sgio_cmd));
	sd->events = malloc(td->o.iodepth * sizeof(struct io_u *));
	memset(sd->events, 0, td->o.iodepth * sizeof(struct io_u *));
	sd->pfds = malloc(sizeof(struct pollfd) * td->o.nr_files);
	memset(sd->pfds, 0, sizeof(struct pollfd) * td->o.nr_files);
	sd->fd_flags = malloc(sizeof(int) * td->o.nr_files);
	memset(sd->fd_flags, 0, sizeof(int) * td->o.nr_files);
	sd->sgbuf = malloc(sizeof(struct sg_io_hdr) * td->o.iodepth);
	memset(sd->sgbuf, 0, sizeof(struct sg_io_hdr) * td->o.iodepth);

	td->io_ops->data = sd;

	/*
	 * we want to do it, regardless of whether odirect is set or not
	 */
	td->o.override_sync = 1;
	return 0;
}

static int fio_sgio_type_check(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops->data;
	unsigned int bs;

	if (f->filetype == FIO_TYPE_BD) {
		if (ioctl(f->fd, BLKSSZGET, &bs) < 0) {
			td_verror(td, errno, "ioctl");
			return 1;
		}
	} else if (f->filetype == FIO_TYPE_CHAR) {
		int version, ret;

		if (ioctl(f->fd, SG_GET_VERSION_NUM, &version) < 0) {
			td_verror(td, errno, "ioctl");
			return 1;
		}

		ret = fio_sgio_get_bs(td, &bs);
		if (ret)
			return 1;
	} else {
		log_err("ioengine sg only works on block devices\n");
		return 1;
	}

	sd->bs = bs;

	if (f->filetype == FIO_TYPE_BD) {
		td->io_ops->getevents = NULL;
		td->io_ops->event = NULL;
	}

	return 0;
}

static int fio_sgio_open(struct thread_data *td, struct fio_file *f)
{
	struct sgio_data *sd = td->io_ops->data;
	int ret;

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	if (sd && !sd->type_checked && fio_sgio_type_check(td, f)) {
		ret = generic_close_file(td, f);
		return 1;
	}

	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "sg",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sgio_init,
	.prep		= fio_sgio_prep,
	.queue		= fio_sgio_queue,
	.getevents	= fio_sgio_getevents,
	.event		= fio_sgio_event,
	.cleanup	= fio_sgio_cleanup,
	.open_file	= fio_sgio_open,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO | FIO_RAWIO,
};

#else /* FIO_HAVE_SGIO */

/*
 * When we have a proper configure system in place, we simply wont build
 * and install this io engine. For now install a crippled version that
 * just complains and fails to load.
 */
static int fio_sgio_init(struct thread_data fio_unused *td)
{
	log_err("fio: ioengine sg not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "sg",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_sgio_init,
};

#endif

static void fio_init fio_sgio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_sgio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
