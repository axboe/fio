/*
 * The io parts of the fio tool, includes workers for sync and mmap'ed
 * io, as well as both posix and linux libaio support.
 *
 * sync io is implemented on top of aio.
 *
 * This is not really specific to fio, if the get_io_u/put_io_u and
 * structures was pulled into this as well it would be a perfectly
 * generic io engine that could be used for other projects.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <sys/mman.h>
#include "fio.h"
#include "os.h"

#ifdef FIO_HAVE_LIBAIO

#define ev_to_iou(ev)	(struct io_u *) ((unsigned long) (ev)->obj)

static int fio_io_sync(struct thread_data *td)
{
	return fsync(td->fd);
}

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

struct libaio_data {
	io_context_t aio_ctx;
	struct io_event *aio_events;
};

static int fio_libaio_io_prep(struct thread_data *td, struct io_u *io_u)
{
	if (io_u->ddir == DDIR_READ)
		io_prep_pread(&io_u->iocb, td->fd, io_u->buf, io_u->buflen, io_u->offset);
	else
		io_prep_pwrite(&io_u->iocb, td->fd, io_u->buf, io_u->buflen, io_u->offset);

	return 0;
}

static struct io_u *fio_libaio_event(struct thread_data *td, int event)
{
	struct libaio_data *ld = td->io_data;

	return ev_to_iou(ld->aio_events + event);
}

static int fio_libaio_getevents(struct thread_data *td, int min, int max,
				struct timespec *t)
{
	struct libaio_data *ld = td->io_data;
	int r;

	do {
		r = io_getevents(ld->aio_ctx, min, max, ld->aio_events, t);
		if (r == -EAGAIN) {
			usleep(100);
			continue;
		} else if (r == -EINTR)
			continue;
		else
			break;
	} while (1);

	return r;
}

static int fio_libaio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_data;
	struct iocb *iocb = &io_u->iocb;
	int ret;

	do {
		ret = io_submit(ld->aio_ctx, 1, &iocb);
		if (ret == 1)
			return 0;
		else if (ret == -EAGAIN)
			usleep(100);
		else if (ret == -EINTR)
			continue;
		else
			break;
	} while (1);

	return ret;

}

static int fio_libaio_cancel(struct thread_data *td, struct io_u *io_u)
{
	struct libaio_data *ld = td->io_data;

	return io_cancel(ld->aio_ctx, &io_u->iocb, ld->aio_events);
}

static void fio_libaio_cleanup(struct thread_data *td)
{
	struct libaio_data *ld = td->io_data;

	if (ld) {
		io_destroy(ld->aio_ctx);
		if (ld->aio_events)
			free(ld->aio_events);

		free(ld);
		td->io_data = NULL;
	}
}

int fio_libaio_init(struct thread_data *td)
{
	struct libaio_data *ld = malloc(sizeof(*ld));

	memset(ld, 0, sizeof(*ld));
	if (io_queue_init(td->iodepth, &ld->aio_ctx)) {
		td_verror(td, errno);
		return 1;
	}

	td->io_prep = fio_libaio_io_prep;
	td->io_queue = fio_libaio_queue;
	td->io_getevents = fio_libaio_getevents;
	td->io_event = fio_libaio_event;
	td->io_cancel = fio_libaio_cancel;
	td->io_cleanup = fio_libaio_cleanup;
	td->io_sync = fio_io_sync;

	ld->aio_events = malloc(td->iodepth * sizeof(struct io_event));
	td->io_data = ld;
	return 0;
}

#else /* FIO_HAVE_LIBAIO */

int fio_libaio_init(struct thread_data *td)
{
	return EINVAL;
}

#endif /* FIO_HAVE_LIBAIO */

#ifdef FIO_HAVE_POSIXAIO

struct posixaio_data {
	struct io_u **aio_events;
};

static int fio_posixaio_cancel(struct thread_data *td, struct io_u *io_u)
{
	int r = aio_cancel(td->fd, &io_u->aiocb);

	if (r == 1 || r == AIO_CANCELED)
		return 0;

	return 1;
}

static int fio_posixaio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct aiocb *aiocb = &io_u->aiocb;

	aiocb->aio_fildes = td->fd;
	aiocb->aio_buf = io_u->buf;
	aiocb->aio_nbytes = io_u->buflen;
	aiocb->aio_offset = io_u->offset;

	io_u->seen = 0;
	return 0;
}

static int fio_posixaio_getevents(struct thread_data *td, int min, int max,
				  struct timespec *t)
{
	struct posixaio_data *pd = td->io_data;
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
	struct posixaio_data *pd = td->io_data;

	return pd->aio_events[event];
}

static int fio_posixaio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct aiocb *aiocb = &io_u->aiocb;
	int ret;

	if (io_u->ddir == DDIR_READ)
		ret = aio_read(aiocb);
	else
		ret = aio_write(aiocb);

	if (ret)
		io_u->error = errno;
		
	return io_u->error;
}

static void fio_posixaio_cleanup(struct thread_data *td)
{
	struct posixaio_data *pd = td->io_data;

	if (pd) {
		free(pd->aio_events);
		free(pd);
		td->io_data = NULL;
	}
}

int fio_posixaio_init(struct thread_data *td)
{
	struct posixaio_data *pd = malloc(sizeof(*pd));

	pd->aio_events = malloc(td->iodepth * sizeof(struct io_u *));

	td->io_prep = fio_posixaio_prep;
	td->io_queue = fio_posixaio_queue;
	td->io_getevents = fio_posixaio_getevents;
	td->io_event = fio_posixaio_event;
	td->io_cancel = fio_posixaio_cancel;
	td->io_cleanup = fio_posixaio_cleanup;
	td->io_sync = fio_io_sync;

	td->io_data = pd;
	return 0;
}

#else /* FIO_HAVE_POSIXAIO */

int fio_posixaio_init(struct thread_data *td)
{
	return EINVAL;
}

#endif /* FIO_HAVE_POSIXAIO */

struct syncio_data {
	struct io_u *last_io_u;
};

static int fio_syncio_getevents(struct thread_data *td, int min, int max,
				struct timespec *t)
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

static struct io_u *fio_syncio_event(struct thread_data *td, int event)
{
	struct syncio_data *sd = td->io_data;

	assert(event == 0);

	return sd->last_io_u;
}

static int fio_syncio_prep(struct thread_data *td, struct io_u *io_u)
{
	if (lseek(td->fd, io_u->offset, SEEK_SET) == -1) {
		td_verror(td, errno);
		return 1;
	}

	return 0;
}

static int fio_syncio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct syncio_data *sd = td->io_data;
	int ret;

	if (io_u->ddir == DDIR_READ)
		ret = read(td->fd, io_u->buf, io_u->buflen);
	else
		ret = write(td->fd, io_u->buf, io_u->buflen);

	if ((unsigned int) ret != io_u->buflen) {
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

static void fio_syncio_cleanup(struct thread_data *td)
{
	if (td->io_data) {
		free(td->io_data);
		td->io_data = NULL;
	}
}

int fio_syncio_init(struct thread_data *td)
{
	struct syncio_data *sd = malloc(sizeof(*sd));

	td->io_prep = fio_syncio_prep;
	td->io_queue = fio_syncio_queue;
	td->io_getevents = fio_syncio_getevents;
	td->io_event = fio_syncio_event;
	td->io_cancel = NULL;
	td->io_cleanup = fio_syncio_cleanup;
	td->io_sync = fio_io_sync;

	sd->last_io_u = NULL;
	td->io_data = sd;
	return 0;
}

static int fio_mmapio_queue(struct thread_data *td, struct io_u *io_u)
{
	unsigned long long real_off = io_u->offset - td->file_offset;
	struct syncio_data *sd = td->io_data;

	if (io_u->ddir == DDIR_READ)
		memcpy(io_u->buf, td->mmap + real_off, io_u->buflen);
	else
		memcpy(td->mmap + real_off, io_u->buf, io_u->buflen);

	/*
	 * not really direct, but should drop the pages from the cache
	 */
	if (td->odirect) {
		if (msync(td->mmap + real_off, io_u->buflen, MS_SYNC) < 0)
			io_u->error = errno;
		if (madvise(td->mmap + real_off, io_u->buflen,  MADV_DONTNEED) < 0)
			io_u->error = errno;
	}

	if (!io_u->error)
		sd->last_io_u = io_u;

	return io_u->error;
}

static int fio_mmapio_sync(struct thread_data *td)
{
	return msync(td->mmap, td->file_size, MS_SYNC);
}

int fio_mmapio_init(struct thread_data *td)
{
	struct syncio_data *sd = malloc(sizeof(*sd));

	td->io_prep = NULL;
	td->io_queue = fio_mmapio_queue;
	td->io_getevents = fio_syncio_getevents;
	td->io_event = fio_syncio_event;
	td->io_cancel = NULL;
	td->io_cleanup = fio_syncio_cleanup;
	td->io_sync = fio_mmapio_sync;

	sd->last_io_u = NULL;
	td->io_data = sd;
	return 0;
}

#ifdef FIO_HAVE_SGIO

struct sgio_data {
	struct io_u *last_io_u;
	unsigned char cdb[10];
	unsigned int bs;
};

static inline void sgio_hdr_init(struct sgio_data *sd, struct sg_io_hdr *hdr,
				 struct io_u *io_u)
{
	memset(hdr, 0, sizeof(*hdr));
	memset(sd->cdb, 0, sizeof(sd->cdb));

	hdr->interface_id = 'S';
	hdr->cmdp = sd->cdb;
	hdr->cmd_len = sizeof(sd->cdb);

	if (io_u) {
		hdr->dxferp = io_u->buf;
		hdr->dxfer_len = io_u->buflen;
	}
}

static int fio_sgio_doio(struct thread_data *td, struct sg_io_hdr *hdr)
{
	int ret;

	if (td->filetype == FIO_TYPE_BD)
		return ioctl(td->fd, SG_IO, &hdr);

	ret = write(td->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return errno;

	ret = read(td->fd, hdr, sizeof(*hdr));
	if (ret < 0)
		return errno;

	return 0;
}

static int fio_sgio_sync(struct thread_data *td)
{
	struct sgio_data *sd = td->io_data;
	struct sg_io_hdr hdr;

	sgio_hdr_init(sd, &hdr, NULL);
	hdr.dxfer_direction = SG_DXFER_NONE;

	hdr.cmdp[0] = 0x35;

	return fio_sgio_doio(td, &hdr);
}

static int fio_sgio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_data;
	int nr_blocks, lba;

	if (io_u->buflen & (sd->bs - 1)) {
		fprintf(stderr, "read/write not sector aligned\n");
		return EINVAL;
	}

	sgio_hdr_init(sd, hdr, io_u);

	if (io_u->ddir == DDIR_READ) {
		hdr->dxfer_direction = SG_DXFER_FROM_DEV;
		hdr->cmdp[0] = 0x28;
	} else {
		hdr->dxfer_direction = SG_DXFER_TO_DEV;
		hdr->cmdp[0] = 0x2a;
	}

	nr_blocks = io_u->buflen / sd->bs;
	lba = io_u->offset / sd->bs;
	hdr->cmdp[2] = (lba >> 24) & 0xff;
	hdr->cmdp[3] = (lba >> 16) & 0xff;
	hdr->cmdp[4] = (lba >>  8) & 0xff;
	hdr->cmdp[5] = lba & 0xff;
	hdr->cmdp[7] = (nr_blocks >> 8) & 0xff;
	hdr->cmdp[8] = nr_blocks & 0xff;
	return 0;
}

static int fio_sgio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct sg_io_hdr *hdr = &io_u->hdr;
	struct sgio_data *sd = td->io_data;
	int ret;

	ret = fio_sgio_doio(td, hdr);

	if (ret < 0)
		io_u->error = errno;
	else if (hdr->status) {
		io_u->resid = hdr->resid;
		io_u->error = EIO;
	}

	if (!io_u->error)
		sd->last_io_u = io_u;

	return io_u->error;
}

static struct io_u *fio_sgio_event(struct thread_data *td, int event)
{
	struct sgio_data *sd = td->io_data;

	assert(event == 0);

	return sd->last_io_u;
}

static int fio_sgio_get_bs(struct thread_data *td, unsigned int *bs)
{
	struct sgio_data *sd = td->io_data;
	struct sg_io_hdr hdr;
	unsigned char buf[8];
	int ret;

	sgio_hdr_init(sd, &hdr, NULL);
	memset(buf, 0, sizeof(buf));

	hdr.cmdp[0] = 0x25;
	hdr.dxfer_direction = SG_DXFER_FROM_DEV;
	hdr.dxferp = buf;
	hdr.dxfer_len = sizeof(buf);

	ret = fio_sgio_doio(td, &hdr);
	if (ret)
		return ret;

	*bs = (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7];
	return 0;
}

int fio_sgio_init(struct thread_data *td)
{
	struct sgio_data *sd;
	unsigned int bs;
	int ret;

	sd = malloc(sizeof(*sd));
	sd->last_io_u = NULL;
	td->io_data = sd;

	if (td->filetype == FIO_TYPE_BD) {
		if (ioctl(td->fd, BLKSSZGET, &bs) < 0) {
			td_verror(td, errno);
			return 1;
		}
	} else if (td->filetype == FIO_TYPE_CHAR) {
		int version;

		if (ioctl(td->fd, SG_GET_VERSION_NUM, &version) < 0) {
			td_verror(td, errno);
			return 1;
		}

		ret = fio_sgio_get_bs(td, &bs);
		if (ret)
			return ret;
	} else {
		fprintf(stderr, "ioengine sgio only works on block devices\n");
		return 1;
	}

	sd->bs = bs;

	td->io_prep = fio_sgio_prep;
	td->io_queue = fio_sgio_queue;
	td->io_getevents = fio_syncio_getevents;
	td->io_event = fio_sgio_event;
	td->io_cancel = NULL;
	td->io_cleanup = fio_syncio_cleanup;
	td->io_sync = fio_sgio_sync;

	/*
	 * we want to do it, regardless of whether odirect is set or not
	 */
	td->override_sync = 1;
	return 0;
}

#else /* FIO_HAVE_SGIO */

int fio_sgio_init(struct thread_data *td)
{
	return EINVAL;
}

#endif /* FIO_HAVE_SGIO */
