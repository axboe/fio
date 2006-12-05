/*
 * scsi generic sg v3 io engine
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

#ifdef FIO_HAVE_SGIO

struct sgio_cmd {
	unsigned char cdb[10];
	int nr;
};

struct sgio_data {
	struct sgio_cmd *cmds;
	struct io_u **events;
	unsigned int bs;
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
		hdr->dxferp = io_u->buf;
		hdr->dxfer_len = io_u->buflen;
	}
}

static int fio_sgio_ioctl_getevents(struct thread_data *td, int fio_unused min,
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


static int fio_sgio_getevents(struct thread_data *td, int min, int max,
			      struct timespec fio_unused *t)
{
	struct fio_file *f = &td->files[0];
	struct sgio_data *sd = td->io_ops->data;
	struct pollfd pfd = { .fd = f->fd, .events = POLLIN };
	void *buf = malloc(max * sizeof(struct sg_io_hdr));
	int left = max, ret, events, i, r = 0, fl = 0;

	/*
	 * don't block for !events
	 */
	if (!min) {
		fl = fcntl(f->fd, F_GETFL);
		fcntl(f->fd, F_SETFL, fl | O_NONBLOCK);
	}

	while (left) {
		do {
			if (!min)
				break;
			poll(&pfd, 1, -1);
			if (pfd.revents & POLLIN)
				break;
		} while (1);

		ret = read(f->fd, buf, left * sizeof(struct sg_io_hdr));
		if (ret < 0) {
			if (errno == EAGAIN)
				break;
			td_verror(td, errno);
			r = -1;
			break;
		} else if (!ret)
			break;

		events = ret / sizeof(struct sg_io_hdr);
		left -= events;
		r += events;

		for (i = 0; i < events; i++) {
			struct sg_io_hdr *hdr = (struct sg_io_hdr *) buf + i;

			sd->events[i] = hdr->usr_ptr;
		}
	}

	if (!min)
		fcntl(f->fd, F_SETFL, fl);

	free(buf);
	return r;
}

static int fio_sgio_ioctl_doio(struct thread_data *td,
			       struct fio_file *f, struct io_u *io_u)
{
	struct sgio_data *sd = td->io_ops->data;
	struct sg_io_hdr *hdr = &io_u->hdr;

	sd->events[0] = io_u;

	return ioctl(f->fd, SG_IO, hdr);
}

static int fio_sgio_rw_doio(struct fio_file *f, struct io_u *io_u, int sync)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	int ret;

	ret = write(f->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return errno;

	if (sync) {
		ret = read(f->fd, hdr, sizeof(*hdr));
		if (ret < 0)
			return errno;
	}

	return 0;
}

static int fio_sgio_doio(struct thread_data *td, struct io_u *io_u, int sync)
{
	struct fio_file *f = io_u->file;

	if (td->filetype == FIO_TYPE_BD)
		return fio_sgio_ioctl_doio(td, f, io_u);

	return fio_sgio_rw_doio(f, io_u, sync);
}

static int fio_sgio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_ops->data;
	int nr_blocks, lba;

	if (io_u->buflen & (sd->bs - 1)) {
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
		nr_blocks = io_u->buflen / sd->bs;
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
	int ret;

	ret = fio_sgio_doio(td, io_u, io_u->ddir == DDIR_SYNC);

	if (ret < 0)
		io_u->error = errno;
	else if (hdr->status) {
		io_u->resid = hdr->resid;
		io_u->error = EIO;
	}

	return io_u->error;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_ops->data;

	return sd->events[event];
}

static int fio_sgio_get_bs(struct thread_data *td, unsigned int *bs)
{
	struct sgio_data *sd = td->io_ops->data;
	struct io_u *io_u;
	struct sg_io_hdr *hdr;
	unsigned char buf[8];
	int ret;

	io_u = __get_io_u(td);
	assert(io_u);

	hdr = &io_u->hdr;
	sgio_hdr_init(sd, hdr, io_u, 0);
	memset(buf, 0, sizeof(buf));

	hdr->cmdp[0] = 0x25;
	hdr->dxfer_direction = SG_DXFER_FROM_DEV;
	hdr->dxferp = buf;
	hdr->dxfer_len = sizeof(buf);

	ret = fio_sgio_doio(td, io_u, 1);
	if (ret) {
		put_io_u(td, io_u);
		return ret;
	}

	*bs = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	put_io_u(td, io_u);
	return 0;
}

static void fio_sgio_cleanup(struct thread_data *td)
{
	if (td->io_ops->data) {
		free(td->io_ops->data);
		td->io_ops->data = NULL;
	}
}

static int fio_sgio_init(struct thread_data *td)
{
	struct fio_file *f = &td->files[0];
	struct sgio_data *sd;
	unsigned int bs;
	int ret;

	sd = malloc(sizeof(*sd));
	memset(sd, 0, sizeof(*sd));
	sd->cmds = malloc(td->iodepth * sizeof(struct sgio_cmd));
	memset(sd->cmds, 0, td->iodepth * sizeof(struct sgio_cmd));
	sd->events = malloc(td->iodepth * sizeof(struct io_u *));
	memset(sd->events, 0, td->iodepth * sizeof(struct io_u *));
	td->io_ops->data = sd;

	if (td->filetype == FIO_TYPE_BD) {
		if (ioctl(f->fd, BLKSSZGET, &bs) < 0) {
			td_verror(td, errno);
			goto err;
		}
	} else if (td->filetype == FIO_TYPE_CHAR) {
		int version;

		if (ioctl(f->fd, SG_GET_VERSION_NUM, &version) < 0) {
			td_verror(td, errno);
			goto err;
		}

		ret = fio_sgio_get_bs(td, &bs);
		if (ret)
			goto err;
	} else {
		log_err("ioengine sgio only works on block devices\n");
		goto err;
	}

	sd->bs = bs;

	if (td->filetype == FIO_TYPE_BD)
		td->io_ops->getevents = fio_sgio_ioctl_getevents;
	else
		td->io_ops->getevents = fio_sgio_getevents;

	/*
	 * we want to do it, regardless of whether odirect is set or not
	 */
	td->override_sync = 1;
	return 0;
err:
	free(sd->events);
	free(sd->cmds);
	free(sd);
	return 1;
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
	fprintf(stderr, "fio: sgio not available\n");
	return 1;
}

static struct ioengine_ops ioengine = {
	.name		= "sgio",
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
