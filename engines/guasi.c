/*
 * guasi engine
 *
 * IO engine using the GUASI library.
 *
 * This is currently disabled. To enable it, execute:
 *
 * $ export EXTFLAGS="-DFIO_HAVE_GUASI"
 * $ export EXTLIBS="-lguasi"
 *
 * before running make. You'll need the GUASI lib as well:
 *
 * http://www.xmailserver.org/guasi-lib.html
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>

#include "../fio.h"

#define GFIO_MIN_THREADS 32
#ifndef GFIO_MAX_THREADS
#define GFIO_MAX_THREADS 2000
#endif

#include <guasi.h>
#include <guasi_syscalls.h>

#ifdef GFIO_DEBUG
#define GDBG_PRINT(a) printf a
#else
#define GDBG_PRINT(a) (void) 0
#endif

struct guasi_data {
	guasi_t hctx;
	int max_reqs;
	guasi_req_t *reqs;
	struct io_u **io_us;
	int queued_nr;
	int reqs_nr;
};

static int fio_guasi_prep(struct thread_data fio_unused *td, struct io_u *io_u)
{

	GDBG_PRINT(("fio_guasi_prep(%p)\n", io_u));
	io_u->greq = NULL;

	return 0;
}

static struct io_u *fio_guasi_event(struct thread_data *td, int event)
{
	struct guasi_data *ld = td->io_ops->data;
	struct io_u *io_u;
	struct guasi_reqinfo rinf;

	GDBG_PRINT(("fio_guasi_event(%d)\n", event));
	if (guasi_req_info(ld->reqs[event], &rinf) < 0) {
		log_err("guasi_req_info(%d) FAILED!\n", event);
		return NULL;
	}
	io_u = rinf.asid;
	io_u->error = EINPROGRESS;
	GDBG_PRINT(("fio_guasi_event(%d) -> %p\n", event, io_u));
	if (rinf.status == GUASI_STATUS_COMPLETE) {
		io_u->error = rinf.result;
		if (io_u->ddir == DDIR_READ ||
		    io_u->ddir == DDIR_WRITE) {
			io_u->error = 0;
			if (rinf.result != (long) io_u->xfer_buflen) {
				if (rinf.result >= 0)
					io_u->resid = io_u->xfer_buflen - rinf.result;
				else
					io_u->error = rinf.error;
			}
		}
	}

	return io_u;
}

static int fio_guasi_getevents(struct thread_data *td, unsigned int min,
			       unsigned int max, struct timespec *t)
{
	struct guasi_data *ld = td->io_ops->data;
	int n, r;
	long timeo = -1;

	GDBG_PRINT(("fio_guasi_getevents(%d, %d)\n", min, max));
	if (min > ld->max_reqs)
		min = ld->max_reqs;
	if (max > ld->max_reqs)
		max = ld->max_reqs;
	if (t)
		timeo = t->tv_sec * 1000L + t->tv_nsec / 1000000L;
	for (n = 0; n < ld->reqs_nr; n++)
		guasi_req_free(ld->reqs[n]);
	n = 0;
	do {
		r = guasi_fetch(ld->hctx, ld->reqs + n, min - n,
				max - n, timeo);
		if (r < 0) {
			log_err("guasi_fetch() FAILED! (%d)\n", r);
			break;
		}
		n += r;
		if (n >= min)
			break;
	} while (1);
	ld->reqs_nr = n;
	GDBG_PRINT(("fio_guasi_getevents() -> %d\n", n));

	return n;
}

static int fio_guasi_queue(struct thread_data *td, struct io_u *io_u)
{
	struct guasi_data *ld = td->io_ops->data;

	fio_ro_check(td, io_u);

	GDBG_PRINT(("fio_guasi_queue(%p)\n", io_u));
	if (ld->queued_nr == (int) td->o.iodepth)
		return FIO_Q_BUSY;

	ld->io_us[ld->queued_nr] = io_u;
	ld->queued_nr++;
	return FIO_Q_QUEUED;
}

static void fio_guasi_queued(struct thread_data *td, struct io_u **io_us, int nr)
{
	int i;
	struct io_u *io_u;
	struct timeval now;

	if (!fio_fill_issue_time(td))
		return;

	io_u_mark_submit(td, nr);
	fio_gettime(&now, NULL);
	for (i = 0; i < nr; i++) {
		io_u = io_us[i];
		memcpy(&io_u->issue_time, &now, sizeof(now));
		io_u_queued(td, io_u);
	}
}

static int fio_guasi_commit(struct thread_data *td)
{
	struct guasi_data *ld = td->io_ops->data;
	int i;
	struct io_u *io_u;
	struct fio_file *f;

	GDBG_PRINT(("fio_guasi_commit(%d)\n", ld->queued_nr));
	for (i = 0; i < ld->queued_nr; i++) {
		io_u = ld->io_us[i];
		GDBG_PRINT(("fio_guasi_commit(%d) --> %p\n", i, io_u));
		f = io_u->file;
		io_u->greq = NULL;
		if (io_u->ddir == DDIR_READ)
			io_u->greq = guasi__pread(ld->hctx, ld, io_u, 0,
						  f->fd, io_u->xfer_buf, io_u->xfer_buflen,
						  io_u->offset);
		else if (io_u->ddir == DDIR_WRITE)
			io_u->greq = guasi__pwrite(ld->hctx, ld, io_u, 0,
						   f->fd, io_u->xfer_buf, io_u->xfer_buflen,
						   io_u->offset);
		else if (ddir_sync(io_u->ddir))
			io_u->greq = guasi__fsync(ld->hctx, ld, io_u, 0, f->fd);
		else {
			log_err("fio_guasi_commit() FAILED: unknow request %d\n",
				io_u->ddir);
		}
		if (io_u->greq == NULL) {
			log_err("fio_guasi_commit() FAILED: submit failed (%s)\n",
				strerror(errno));
			return -1;
		}
	}
	fio_guasi_queued(td, ld->io_us, i);
	ld->queued_nr = 0;
	GDBG_PRINT(("fio_guasi_commit() -> %d\n", i));

	return 0;
}

static int fio_guasi_cancel(struct thread_data fio_unused *td,
			    struct io_u *io_u)
{
	GDBG_PRINT(("fio_guasi_cancel(%p) req=%p\n", io_u, io_u->greq));
	if (io_u->greq != NULL)
		guasi_req_cancel(io_u->greq);

	return 0;
}

static void fio_guasi_cleanup(struct thread_data *td)
{
	struct guasi_data *ld = td->io_ops->data;
	int n;

	GDBG_PRINT(("fio_guasi_cleanup(%p)\n", ld));
	if (ld) {
		for (n = 0; n < ld->reqs_nr; n++)
			guasi_req_free(ld->reqs[n]);
		guasi_free(ld->hctx);
		free(ld->reqs);
		free(ld->io_us);
		free(ld);
	}
	GDBG_PRINT(("fio_guasi_cleanup(%p) DONE\n", ld));
}

static int fio_guasi_init(struct thread_data *td)
{
	int maxthr;
	struct guasi_data *ld = malloc(sizeof(*ld));

	GDBG_PRINT(("fio_guasi_init(): depth=%d\n", td->o.iodepth));
	memset(ld, 0, sizeof(*ld));
	maxthr = td->o.iodepth > GFIO_MIN_THREADS ? td->o.iodepth: GFIO_MIN_THREADS;
	if (maxthr > GFIO_MAX_THREADS)
		maxthr = GFIO_MAX_THREADS;
	if ((ld->hctx = guasi_create(GFIO_MIN_THREADS, maxthr, 1)) == NULL) {
		td_verror(td, errno, "guasi_create");
		free(ld);
		return 1;
	}
	ld->max_reqs = td->o.iodepth;
	ld->reqs = malloc(ld->max_reqs * sizeof(guasi_req_t));
	ld->io_us = malloc(ld->max_reqs * sizeof(struct io_u *));
	memset(ld->io_us, 0, ld->max_reqs * sizeof(struct io_u *));
	ld->queued_nr = 0;
	ld->reqs_nr = 0;

	td->io_ops->data = ld;
	GDBG_PRINT(("fio_guasi_init(): depth=%d -> %p\n", td->o.iodepth, ld));

	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "guasi",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_guasi_init,
	.prep		= fio_guasi_prep,
	.queue		= fio_guasi_queue,
	.commit		= fio_guasi_commit,
	.cancel		= fio_guasi_cancel,
	.getevents	= fio_guasi_getevents,
	.event		= fio_guasi_event,
	.cleanup	= fio_guasi_cleanup,
	.open_file	= generic_open_file,
	.close_file	= generic_close_file,
	.get_file_size	= generic_get_file_size,
};

static void fio_init fio_guasi_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_guasi_unregister(void)
{
	unregister_ioengine(&ioengine);
}

