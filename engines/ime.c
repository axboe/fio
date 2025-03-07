/*
 * FIO engines for DDN's Infinite Memory Engine.
 * This file defines 3 engines: ime_psync, ime_psyncv, and ime_aio
 *
 * Copyright (C) 2018      DataDirect Networks. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

/*
 * Some details about the new engines are given below:
 *
 *
 * ime_psync:
 * Most basic engine that issues calls to ime_native whenever an IO is queued.
 *
 * ime_psyncv:
 * This engine tries to queue the IOs (by creating iovecs) if asked by FIO (via
 * iodepth_batch). It refuses to queue when the iovecs can't be appended, and
 * waits for FIO to issue a commit. After a call to commit and get_events, new
 * IOs can be queued.
 *
 * ime_aio:
 * This engine tries to queue the IOs (by creating iovecs) if asked by FIO (via
 * iodepth_batch). When the iovecs can't be appended to the current request, a
 * new request for IME is created. These requests will be issued to IME when
 * commit is called. Contrary to ime_psyncv, there can be several requests at
 * once. We don't need to wait for a request to terminate before creating a new
 * one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <linux/limits.h>
#include <ime_native.h>

#include "../fio.h"


/**************************************************************
 *              Types and constants definitions
 *
 **************************************************************/

/* define constants for async IOs */
#define FIO_IME_IN_PROGRESS -1
#define FIO_IME_REQ_ERROR   -2

/* This flag is used when some jobs were created using threads. In that
   case, IME can't be finalized in the engine-specific cleanup function,
   because other threads might still use IME. Instead, IME is finalized
   in the destructor (see fio_ime_unregister), only when the flag
   fio_ime_is_initialized is true (which means at least one thread has
   initialized IME). */
static bool fio_ime_is_initialized = false;

struct imesio_req {
	int 			fd;		/* File descriptor */
	enum fio_ddir	ddir;	/* Type of IO (read or write) */
	off_t			offset;	/* File offset */
};
struct imeaio_req {
	struct ime_aiocb 	iocb;			/* IME aio request */
	ssize_t      		status;			/* Status of the IME request */
	enum fio_ddir		ddir;			/* Type of IO (read or write) */
	pthread_cond_t		cond_endio;		/* Condition var to notify FIO */
	pthread_mutex_t		status_mutex;	/* Mutex for cond_endio */
};

/* This structure will be used for 2 engines: ime_psyncv and ime_aio */
struct ime_data {
	union {
		struct imeaio_req 	*aioreqs;	/* array of aio requests */
		struct imesio_req	*sioreq;	/* pointer to the only syncio request */
	};
	struct iovec 	*iovecs;		/* array of queued iovecs */
	struct io_u 	**io_us;		/* array of queued io_u pointers */
	struct io_u 	**event_io_us;	/* array of the events retrieved after get_events*/
	unsigned int 	queued;			/* iovecs/io_us in the queue */
	unsigned int 	events;			/* number of committed iovecs/io_us */

	/* variables used to implement a "ring" queue */
	unsigned int depth;			/* max entries in the queue */
	unsigned int head;			/* index used to append */
	unsigned int tail;			/* index used to pop */
	unsigned int cur_commit;	/* index of the first uncommitted req */

	/* offset used by the last iovec (used to check if the iovecs can be appended)*/
	unsigned long long	last_offset;

	/* The variables below are used for aio only */
	struct imeaio_req	*last_req; /* last request awaiting committing */
};


/**************************************************************
 *         Private functions for queueing/unqueueing
 *
 **************************************************************/

static void fio_ime_queue_incr (struct ime_data *ime_d)
{
	ime_d->head = (ime_d->head + 1) % ime_d->depth;
	ime_d->queued++;
}

static void fio_ime_queue_red (struct ime_data *ime_d)
{
	ime_d->tail = (ime_d->tail + 1) % ime_d->depth;
	ime_d->queued--;
	ime_d->events--;
}

static void fio_ime_queue_commit (struct ime_data *ime_d, int iovcnt)
{
	ime_d->cur_commit = (ime_d->cur_commit + iovcnt) % ime_d->depth;
	ime_d->events += iovcnt;
}

static void fio_ime_queue_reset (struct ime_data *ime_d)
{
	ime_d->head = 0;
	ime_d->tail = 0;
	ime_d->cur_commit = 0;
	ime_d->queued = 0;
	ime_d->events = 0;
}

/**************************************************************
 *                   General IME functions
 *             (needed for both sync and async IOs)
 **************************************************************/

static char *fio_set_ime_filename(char* filename)
{
	static __thread char ime_filename[PATH_MAX];
	int ret;

	ret = snprintf(ime_filename, PATH_MAX, "%s%s", DEFAULT_IME_FILE_PREFIX, filename);
	if (ret < PATH_MAX)
		return ime_filename;

	return NULL;
}

static int fio_ime_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct stat buf;
	int ret;
	char *ime_filename;

	dprint(FD_FILE, "get file size %s\n", f->file_name);

	ime_filename = fio_set_ime_filename(f->file_name);
	if (ime_filename == NULL)
		return 1;
	ret = ime_native_stat(ime_filename, &buf);
	if (ret == -1) {
		td_verror(td, errno, "fstat");
		return 1;
	}

	f->real_file_size = buf.st_size;
	return 0;
}

/* This functions mimics the generic_file_open function, but issues
   IME native calls instead of POSIX calls. */
static int fio_ime_open_file(struct thread_data *td, struct fio_file *f)
{
	int flags = 0;
	int ret;
	uint64_t desired_fs;
	char *ime_filename;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (td_trim(td)) {
		td_verror(td, EINVAL, "IME does not support TRIM operation");
		return 1;
	}

	if (td->o.odirect)
		flags |= O_DIRECT;
	flags |= td->o.sync_io;
	if (td->o.create_on_open && td->o.allow_create)
		flags |= O_CREAT;

	if (td_write(td)) {
		if (!read_only)
			flags |= O_RDWR;

		if (td->o.allow_create)
			flags |= O_CREAT;
	} else if (td_read(td)) {
		flags |= O_RDONLY;
	} else {
		/* We should never go here. */
		td_verror(td, EINVAL, "Unsopported open mode");
		return 1;
	}

	ime_filename = fio_set_ime_filename(f->file_name);
	if (ime_filename == NULL)
		return 1;
	f->fd = ime_native_open(ime_filename, flags, 0600);
	if (f->fd == -1) {
		char buf[FIO_VERROR_SIZE];
		int __e = errno;

		snprintf(buf, sizeof(buf), "open(%s)", f->file_name);
		td_verror(td, __e, buf);
		return 1;
	}

	/* Now we need to make sure the real file size is sufficient for FIO
	   to do its things. This is normally done before the file open function
	   is called, but because FIO would use POSIX calls, we need to do it
	   ourselves */
	ret = fio_ime_get_file_size(td, f);
	if (ret < 0) {
		ime_native_close(f->fd);
		td_verror(td, errno, "ime_get_file_size");
		return 1;
	}

	desired_fs = f->io_size + f->file_offset;
	if (td_write(td)) {
		dprint(FD_FILE, "Laying out file %s%s\n",
			DEFAULT_IME_FILE_PREFIX, f->file_name);
		if (!td->o.create_on_open &&
				f->real_file_size < desired_fs &&
				ime_native_ftruncate(f->fd, desired_fs) < 0) {
			ime_native_close(f->fd);
			td_verror(td, errno, "ime_native_ftruncate");
			return 1;
		}
		if (f->real_file_size < desired_fs)
			f->real_file_size = desired_fs;
	} else if (td_read(td) && f->real_file_size < desired_fs) {
		ime_native_close(f->fd);
		log_err("error: can't read %lu bytes from file with "
						"%lu bytes\n", desired_fs, f->real_file_size);
		return 1;
	}

	return 0;
}

static int fio_ime_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	int ret = 0;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (ime_native_close(f->fd) < 0)
		ret = errno;

	f->fd = -1;
	return ret;
}

static int fio_ime_unlink_file(struct thread_data *td, struct fio_file *f)
{
	char *ime_filename = fio_set_ime_filename(f->file_name);
	int ret;

	if (ime_filename == NULL)
		return 1;

	ret = unlink(ime_filename);
	return ret < 0 ? errno : 0;
}

static struct io_u *fio_ime_event(struct thread_data *td, int event)
{
	struct ime_data *ime_d = td->io_ops_data;

	return ime_d->event_io_us[event];
}

/* Setup file used to replace get_file_sizes when settin up the file.
   Instead we will set real_file_sie to 0 for each file. This way we
   can avoid calling ime_native_init before the forks are created. */
static int fio_ime_setup(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		dprint(FD_FILE, "setup: set file size to 0 for %p/%d/%s\n",
			f, i, f->file_name);
		f->real_file_size = 0;
	}

	return 0;
}

static int fio_ime_engine_init(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	dprint(FD_IO, "ime engine init\n");
	if (fio_ime_is_initialized && !td->o.use_thread) {
		log_err("Warning: something might go wrong. Not all threads/forks were"
				" created before the FIO jobs were initialized.\n");
	}

	ime_native_init();
	fio_ime_is_initialized = true;

	/* We have to temporarily set real_file_size so that
	   FIO can initialize properly. It will be corrected
	   on file open. */
	for_each_file(td, f, i)
		f->real_file_size = f->io_size + f->file_offset;

	return 0;
}

static void fio_ime_engine_finalize(struct thread_data *td)
{
	/* Only finalize IME when using forks */
	if (!td->o.use_thread) {
		if (ime_native_finalize() < 0)
			log_err("error in ime_native_finalize\n");
		fio_ime_is_initialized = false;
	}
}


/**************************************************************
 *             Private functions for blocking IOs
 *                     (without iovecs)
 **************************************************************/

/* Notice: this function comes from the sync engine */
/* It is used by the commit function to return a proper code and fill
   some attributes in the io_u used for the IO. */
static int fio_ime_psync_end(struct thread_data *td, struct io_u *io_u, ssize_t ret)
{
	if (ret != (ssize_t) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error) {
		io_u_log_error(td, io_u);
		td_verror(td, io_u->error, "xfer");
	}

	return FIO_Q_COMPLETED;
}

static enum fio_q_status fio_ime_psync_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	ssize_t ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_READ)
		ret = ime_native_pread(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_WRITE)
		ret = ime_native_pwrite(f->fd, io_u->xfer_buf, io_u->xfer_buflen, io_u->offset);
	else if (io_u->ddir == DDIR_SYNC)
		ret = ime_native_fsync(f->fd);
	else {
		ret = io_u->xfer_buflen;
		io_u->error = EINVAL;
	}

	return fio_ime_psync_end(td, io_u, ret);
}


/**************************************************************
 *             Private functions for blocking IOs
 *                       (with iovecs)
 **************************************************************/

static bool fio_ime_psyncv_can_queue(struct ime_data *ime_d, struct io_u *io_u)
{
	/* We can only queue if:
	  - There are no queued iovecs
	  - Or if there is at least one:
		 - There must be no event waiting for retrieval
		 - The offsets must be contiguous
		 - The ddir and fd must be the same */
	return (ime_d->queued == 0 || (
			ime_d->events == 0 &&
			ime_d->last_offset == io_u->offset &&
			ime_d->sioreq->ddir == io_u->ddir &&
			ime_d->sioreq->fd == io_u->file->fd));
}

/* Before using this function, we should have already
   ensured that the queue is not full */
static void fio_ime_psyncv_enqueue(struct ime_data *ime_d, struct io_u *io_u)
{
	struct imesio_req *ioreq = ime_d->sioreq;
	struct iovec *iov = &ime_d->iovecs[ime_d->head];

	iov->iov_base = io_u->xfer_buf;
	iov->iov_len = io_u->xfer_buflen;

	if (ime_d->queued == 0) {
		ioreq->offset = io_u->offset;
		ioreq->ddir = io_u->ddir;
		ioreq->fd = io_u->file->fd;
	}

	ime_d->io_us[ime_d->head] = io_u;
	ime_d->last_offset = io_u->offset + io_u->xfer_buflen;
	fio_ime_queue_incr(ime_d);
}

/* Tries to queue an IO. It will fail if the IO can't be appended to the
   current request or if the current request has been committed but not
   yet retrieved by get_events. */
static enum fio_q_status fio_ime_psyncv_queue(struct thread_data *td,
	struct io_u *io_u)
{
	struct ime_data *ime_d = td->io_ops_data;

	fio_ro_check(td, io_u);

	if (ime_d->queued == ime_d->depth)
		return FIO_Q_BUSY;

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (!fio_ime_psyncv_can_queue(ime_d, io_u))
			return FIO_Q_BUSY;

		dprint(FD_IO, "queue: ddir=%d at %u commit=%u queued=%u events=%u\n",
			io_u->ddir, ime_d->head, ime_d->cur_commit,
			ime_d->queued, ime_d->events);
		fio_ime_psyncv_enqueue(ime_d, io_u);
		return FIO_Q_QUEUED;
	} else if (io_u->ddir == DDIR_SYNC) {
		if (ime_native_fsync(io_u->file->fd) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "fsync");
		}
		return FIO_Q_COMPLETED;
	} else {
		io_u->error = EINVAL;
		td_verror(td, io_u->error, "wrong ddir");
		return FIO_Q_COMPLETED;
	}
}

/* Notice: this function comes from the sync engine */
/* It is used by the commit function to return a proper code and fill
   some attributes in the io_us appended to the current request. */
static int fio_ime_psyncv_end(struct thread_data *td, ssize_t bytes)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct io_u *io_u;
	unsigned int i;
	int err = errno;

	for (i = 0; i < ime_d->queued; i++) {
		io_u = ime_d->io_us[i];

		if (bytes == -1)
			io_u->error = err;
		else {
			unsigned int this_io;

			this_io = bytes;
			if (this_io > io_u->xfer_buflen)
				this_io = io_u->xfer_buflen;

			io_u->resid = io_u->xfer_buflen - this_io;
			io_u->error = 0;
			bytes -= this_io;
		}
	}

	if (bytes == -1) {
		td_verror(td, err, "xfer psyncv");
		return -err;
	}

	return 0;
}

/* Commits the current request by calling ime_native (with one or several
   iovecs). After this commit, the corresponding events (one per iovec)
   can be retrieved by get_events. */
static int fio_ime_psyncv_commit(struct thread_data *td)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct imesio_req *ioreq;
	int ret = 0;

	/* Exit if there are no (new) events to commit
	   or if the previous committed event haven't been retrieved */
	if (!ime_d->queued || ime_d->events)
		return 0;

	ioreq = ime_d->sioreq;
	ime_d->events = ime_d->queued;
	if (ioreq->ddir == DDIR_READ)
		ret = ime_native_preadv(ioreq->fd, ime_d->iovecs, ime_d->queued, ioreq->offset);
	else
		ret = ime_native_pwritev(ioreq->fd, ime_d->iovecs, ime_d->queued, ioreq->offset);

	dprint(FD_IO, "committed %d iovecs\n", ime_d->queued);

	return fio_ime_psyncv_end(td, ret);
}

static int fio_ime_psyncv_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct io_u *io_u;
	int events = 0;
	unsigned int count;

	if (ime_d->events) {
		for (count = 0; count < ime_d->events; count++) {
			io_u = ime_d->io_us[count];
			ime_d->event_io_us[events] = io_u;
			events++;
		}
		fio_ime_queue_reset(ime_d);
	}

	dprint(FD_IO, "getevents(%u,%u) ret=%d queued=%u events=%u\n",
		min, max, events, ime_d->queued, ime_d->events);
	return events;
}

static int fio_ime_psyncv_init(struct thread_data *td)
{
	struct ime_data *ime_d;

	if (fio_ime_engine_init(td) < 0)
		return 1;

	ime_d = calloc(1, sizeof(*ime_d));

	ime_d->sioreq = malloc(sizeof(struct imesio_req));
	ime_d->iovecs = malloc(td->o.iodepth * sizeof(struct iovec));
	ime_d->io_us = malloc(2 * td->o.iodepth * sizeof(struct io_u *));
	ime_d->event_io_us = ime_d->io_us + td->o.iodepth;

	ime_d->depth = td->o.iodepth;

	td->io_ops_data = ime_d;
	return 0;
}

static void fio_ime_psyncv_clean(struct thread_data *td)
{
	struct ime_data *ime_d = td->io_ops_data;

	if (ime_d) {
		free(ime_d->sioreq);
		free(ime_d->iovecs);
		free(ime_d->io_us);
		free(ime_d);
		td->io_ops_data = NULL;
	}

	fio_ime_engine_finalize(td);
}


/**************************************************************
 *           Private functions for non-blocking IOs
 *
 **************************************************************/

void fio_ime_aio_complete_cb  (struct ime_aiocb *aiocb, int err,
							   ssize_t bytes)
{
	struct imeaio_req *ioreq = (struct imeaio_req *) aiocb->user_context;

	pthread_mutex_lock(&ioreq->status_mutex);
	ioreq->status = err == 0 ? bytes : FIO_IME_REQ_ERROR;
	pthread_mutex_unlock(&ioreq->status_mutex);

	pthread_cond_signal(&ioreq->cond_endio);
}

static bool fio_ime_aio_can_queue (struct ime_data *ime_d, struct io_u *io_u)
{
	/* So far we can queue in any case. */
	return true;
}
static bool fio_ime_aio_can_append (struct ime_data *ime_d, struct io_u *io_u)
{
	/* We can only append if:
		- The iovecs will be contiguous in the array
		- There is already a queued iovec
		- The offsets are contiguous
		- The ddir and fs are the same */
	return (ime_d->head != 0 &&
			ime_d->queued - ime_d->events > 0 &&
			ime_d->last_offset == io_u->offset &&
			ime_d->last_req->ddir == io_u->ddir &&
			ime_d->last_req->iocb.fd == io_u->file->fd);
}

/* Before using this function, we should have already
   ensured that the queue is not full */
static void fio_ime_aio_enqueue(struct ime_data *ime_d, struct io_u *io_u)
{
	struct imeaio_req *ioreq = &ime_d->aioreqs[ime_d->head];
	struct ime_aiocb *iocb = &ioreq->iocb;
	struct iovec *iov = &ime_d->iovecs[ime_d->head];

	iov->iov_base = io_u->xfer_buf;
	iov->iov_len = io_u->xfer_buflen;

	if (fio_ime_aio_can_append(ime_d, io_u))
		ime_d->last_req->iocb.iovcnt++;
	else {
		ioreq->status = FIO_IME_IN_PROGRESS;
		ioreq->ddir = io_u->ddir;
		ime_d->last_req = ioreq;

		iocb->complete_cb = &fio_ime_aio_complete_cb;
		iocb->fd = io_u->file->fd;
		iocb->file_offset = io_u->offset;
		iocb->iov = iov;
		iocb->iovcnt = 1;
		iocb->flags = 0;
		iocb->user_context = (intptr_t) ioreq;
	}

	ime_d->io_us[ime_d->head] = io_u;
	ime_d->last_offset = io_u->offset + io_u->xfer_buflen;
	fio_ime_queue_incr(ime_d);
}

/* Tries to queue an IO. It will create a new request if the IO can't be
   appended to the current request. It will fail if the queue can't contain
   any more io_u/iovec. In this case, commit and then get_events need to be
   called. */
static enum fio_q_status fio_ime_aio_queue(struct thread_data *td,
		struct io_u *io_u)
{
	struct ime_data *ime_d = td->io_ops_data;

	fio_ro_check(td, io_u);

	dprint(FD_IO, "queue: ddir=%d at %u commit=%u queued=%u events=%u\n",
		io_u->ddir, ime_d->head, ime_d->cur_commit,
		ime_d->queued, ime_d->events);

	if (ime_d->queued == ime_d->depth)
		return FIO_Q_BUSY;

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		if (!fio_ime_aio_can_queue(ime_d, io_u))
			return FIO_Q_BUSY;

		fio_ime_aio_enqueue(ime_d, io_u);
		return FIO_Q_QUEUED;
	} else if (io_u->ddir == DDIR_SYNC) {
		if (ime_native_fsync(io_u->file->fd) < 0) {
			io_u->error = errno;
			td_verror(td, io_u->error, "fsync");
		}
		return FIO_Q_COMPLETED;
	} else {
		io_u->error = EINVAL;
		td_verror(td, io_u->error, "wrong ddir");
		return FIO_Q_COMPLETED;
	}
}

static int fio_ime_aio_commit(struct thread_data *td)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct imeaio_req *ioreq;
	int ret = 0;

	/* Loop while there are events to commit */
	while (ime_d->queued - ime_d->events) {
		ioreq = &ime_d->aioreqs[ime_d->cur_commit];
		if (ioreq->ddir == DDIR_READ)
			ret = ime_native_aio_read(&ioreq->iocb);
		else
			ret = ime_native_aio_write(&ioreq->iocb);

		fio_ime_queue_commit(ime_d, ioreq->iocb.iovcnt);

		/* fio needs a negative error code */
		if (ret < 0) {
			ioreq->status = FIO_IME_REQ_ERROR;
			return -errno;
		}

		io_u_mark_submit(td, ioreq->iocb.iovcnt);
		dprint(FD_IO, "committed %d iovecs commit=%u queued=%u events=%u\n",
			ioreq->iocb.iovcnt, ime_d->cur_commit,
			ime_d->queued, ime_d->events);
	}

	return 0;
}

static int fio_ime_aio_getevents(struct thread_data *td, unsigned int min,
				unsigned int max, const struct timespec *t)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct imeaio_req *ioreq;
	struct io_u *io_u;
	int events = 0;
	unsigned int count;
	ssize_t bytes;

	while (ime_d->events) {
		ioreq = &ime_d->aioreqs[ime_d->tail];

		/* Break if we already got events, and if we will
		   exceed max if we append the next events */
		if (events && events + ioreq->iocb.iovcnt > max)
			break;

		if (ioreq->status != FIO_IME_IN_PROGRESS) {

			bytes = ioreq->status;
			for (count = 0; count < ioreq->iocb.iovcnt; count++) {
				io_u = ime_d->io_us[ime_d->tail];
				ime_d->event_io_us[events] = io_u;
				events++;
				fio_ime_queue_red(ime_d);

				if (ioreq->status == FIO_IME_REQ_ERROR)
					io_u->error = EIO;
				else {
					io_u->resid = bytes > io_u->xfer_buflen ?
									0 : io_u->xfer_buflen - bytes;
					io_u->error = 0;
					bytes -= io_u->xfer_buflen - io_u->resid;
				}
			}
		} else {
			pthread_mutex_lock(&ioreq->status_mutex);
			while (ioreq->status == FIO_IME_IN_PROGRESS)
				pthread_cond_wait(&ioreq->cond_endio, &ioreq->status_mutex);
			pthread_mutex_unlock(&ioreq->status_mutex);
		}

	}

	dprint(FD_IO, "getevents(%u,%u) ret=%d queued=%u events=%u\n", min, max,
		events, ime_d->queued, ime_d->events);
	return events;
}

static int fio_ime_aio_init(struct thread_data *td)
{
	struct ime_data *ime_d;
	struct imeaio_req *ioreq;
	unsigned int i;

	if (fio_ime_engine_init(td) < 0)
		return 1;

	ime_d = calloc(1, sizeof(*ime_d));

	ime_d->aioreqs = malloc(td->o.iodepth * sizeof(struct imeaio_req));
	ime_d->iovecs = malloc(td->o.iodepth * sizeof(struct iovec));
	ime_d->io_us = malloc(2 * td->o.iodepth * sizeof(struct io_u *));
	ime_d->event_io_us = ime_d->io_us + td->o.iodepth;

	ime_d->depth = td->o.iodepth;
	for (i = 0; i < ime_d->depth; i++) {
		ioreq = &ime_d->aioreqs[i];
		pthread_cond_init(&ioreq->cond_endio, NULL);
		pthread_mutex_init(&ioreq->status_mutex, NULL);
	}

	td->io_ops_data = ime_d;
	return 0;
}

static void fio_ime_aio_clean(struct thread_data *td)
{
	struct ime_data *ime_d = td->io_ops_data;
	struct imeaio_req *ioreq;
	unsigned int i;

	if (ime_d) {
		for (i = 0; i < ime_d->depth; i++) {
			ioreq = &ime_d->aioreqs[i];
			pthread_cond_destroy(&ioreq->cond_endio);
			pthread_mutex_destroy(&ioreq->status_mutex);
		}
		free(ime_d->aioreqs);
		free(ime_d->iovecs);
		free(ime_d->io_us);
		free(ime_d);
		td->io_ops_data = NULL;
	}

	fio_ime_engine_finalize(td);
}


/**************************************************************
 *                   IO engines definitions
 *
 **************************************************************/

/* The FIO_DISKLESSIO flag used for these engines is necessary to prevent
   FIO from using POSIX calls. See fio_ime_open_file for more details. */

static struct ioengine_ops ioengine_prw = {
	.name		= "ime_psync",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_ime_setup,
	.init		= fio_ime_engine_init,
	.cleanup	= fio_ime_engine_finalize,
	.queue		= fio_ime_psync_queue,
	.open_file	= fio_ime_open_file,
	.close_file	= fio_ime_close_file,
	.get_file_size	= fio_ime_get_file_size,
	.unlink_file  	= fio_ime_unlink_file,
	.flags	    	= FIO_SYNCIO | FIO_DISKLESSIO,
};

static struct ioengine_ops ioengine_pvrw = {
	.name		= "ime_psyncv",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_ime_setup,
	.init		= fio_ime_psyncv_init,
	.cleanup	= fio_ime_psyncv_clean,
	.queue		= fio_ime_psyncv_queue,
	.commit		= fio_ime_psyncv_commit,
	.getevents	= fio_ime_psyncv_getevents,
	.event		= fio_ime_event,
	.open_file	= fio_ime_open_file,
	.close_file	= fio_ime_close_file,
	.get_file_size	= fio_ime_get_file_size,
	.unlink_file  	= fio_ime_unlink_file,
	.flags	    	= FIO_SYNCIO | FIO_DISKLESSIO,
};

static struct ioengine_ops ioengine_aio = {
	.name		= "ime_aio",
	.version	= FIO_IOOPS_VERSION,
	.setup		= fio_ime_setup,
	.init		= fio_ime_aio_init,
	.cleanup	= fio_ime_aio_clean,
	.queue		= fio_ime_aio_queue,
	.commit		= fio_ime_aio_commit,
	.getevents	= fio_ime_aio_getevents,
	.event		= fio_ime_event,
	.open_file	= fio_ime_open_file,
	.close_file	= fio_ime_close_file,
	.get_file_size	= fio_ime_get_file_size,
	.unlink_file  	= fio_ime_unlink_file,
	.flags       	= FIO_DISKLESSIO,
};

static void fio_init fio_ime_register(void)
{
	register_ioengine(&ioengine_prw);
	register_ioengine(&ioengine_pvrw);
	register_ioengine(&ioengine_aio);
}

static void fio_exit fio_ime_unregister(void)
{
	unregister_ioengine(&ioengine_prw);
	unregister_ioengine(&ioengine_pvrw);
	unregister_ioengine(&ioengine_aio);

	if (fio_ime_is_initialized && ime_native_finalize() < 0)
		log_err("Warning: IME did not finalize properly\n");
}
