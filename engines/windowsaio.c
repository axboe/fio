/*
 * windowsaio engine
 *
 * IO engine using Windows IO Completion Ports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "../fio.h"
#include "../optgroup.h"

typedef BOOL (WINAPI *CANCELIOEX)(HANDLE hFile, LPOVERLAPPED lpOverlapped);

int geterrno_from_win_error (DWORD code, int deferrno);

struct fio_overlapped {
	OVERLAPPED o;
	struct io_u *io_u;
	BOOL io_complete;
};

struct windowsaio_data {
	struct io_u **aio_events;
	HANDLE iocp;
	HANDLE iothread;
	HANDLE iocomplete_event;
	BOOL iothread_running;
};

struct thread_ctx {
	HANDLE iocp;
	struct windowsaio_data *wd;
};

struct windowsaio_options {
	struct thread_data *td;
	unsigned int no_completion_thread;
};

static struct fio_option options[] = {
	{
		.name	= "no_completion_thread",
		.lname	= "No completion polling thread",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct windowsaio_options, no_completion_thread),
		.help	= "Use to avoid separate completion polling thread",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_WINDOWSAIO,
	},
	{
		.name	= NULL,
	},
};

static DWORD WINAPI IoCompletionRoutine(LPVOID lpParameter);

static int fio_windowsaio_init(struct thread_data *td)
{
	struct windowsaio_data *wd;
	int rc = 0;

	wd = calloc(1, sizeof(struct windowsaio_data));
	if (wd == NULL) {
		 log_err("windowsaio: failed to allocate memory for engine data\n");
		rc = 1;
	}

	if (!rc) {
		wd->aio_events = malloc(td->o.iodepth * sizeof(struct io_u*));
		if (wd->aio_events == NULL) {
			log_err("windowsaio: failed to allocate memory for aio events list\n");
			rc = 1;
		}
	}

	if (!rc) {
		/* Create an auto-reset event */
		wd->iocomplete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (wd->iocomplete_event == NULL) {
			log_err("windowsaio: failed to create io complete event handle\n");
			rc = 1;
		}
	}

	if (rc) {
		if (wd != NULL) {
			if (wd->aio_events != NULL)
				free(wd->aio_events);

			free(wd);
		}
	}

	td->io_ops_data = wd;

	if (!rc) {
		struct thread_ctx *ctx;
		struct windowsaio_data *wd;
		HANDLE hFile;
		struct windowsaio_options *o = td->eo;

		hFile = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
		if (hFile == INVALID_HANDLE_VALUE) {
			log_err("windowsaio: failed to create io completion port\n");
			rc = 1;
		}

		wd = td->io_ops_data;
		wd->iothread_running = TRUE;
		wd->iocp = hFile;

		if (o->no_completion_thread == 0) {
			if (!rc)
				ctx = malloc(sizeof(struct thread_ctx));

			if (!rc && ctx == NULL) {
				log_err("windowsaio: failed to allocate memory for thread context structure\n");
				CloseHandle(hFile);
				rc = 1;
			}

			if (!rc) {
				DWORD threadid;

				ctx->iocp = hFile;
				ctx->wd = wd;
				wd->iothread = CreateThread(NULL, 0, IoCompletionRoutine, ctx, 0, &threadid);
				if (!wd->iothread)
					log_err("windowsaio: failed to create io completion thread\n");
				else if (fio_option_is_set(&td->o, cpumask))
					fio_setaffinity(threadid, td->o.cpumask);
			}
			if (rc || wd->iothread == NULL)
				rc = 1;
		}
	}

	return rc;
}

static void fio_windowsaio_cleanup(struct thread_data *td)
{
	struct windowsaio_data *wd;

	wd = td->io_ops_data;

	if (wd != NULL) {
		wd->iothread_running = FALSE;
		WaitForSingleObject(wd->iothread, INFINITE);

		CloseHandle(wd->iothread);
		CloseHandle(wd->iocomplete_event);

		free(wd->aio_events);
		free(wd);

		td->io_ops_data = NULL;
	}
}

static int windowsaio_invalidate_cache(struct fio_file *f)
{
	DWORD error;
	DWORD isharemode = (FILE_SHARE_DELETE | FILE_SHARE_READ |
				FILE_SHARE_WRITE);
	HANDLE ihFile;
	int rc = 0;

	/*
	 * Encourage Windows to drop cached parts of a file by temporarily
	 * opening it for non-buffered access. Note: this will only work when
	 * the following is the only thing with the file open on the whole
	 * system.
	 */
	dprint(FD_IO, "windowaio: attempt invalidate cache for %s\n",
			f->file_name);
	ihFile = CreateFile(f->file_name, 0, isharemode, NULL, OPEN_EXISTING,
			FILE_FLAG_NO_BUFFERING, NULL);

	if (ihFile != INVALID_HANDLE_VALUE) {
		if (!CloseHandle(ihFile)) {
			error = GetLastError();
			log_info("windowsaio: invalidation fd close %s failed: error %lu\n",
				 f->file_name, error);
			rc = 1;
		}
	} else {
		error = GetLastError();
		if (error != ERROR_FILE_NOT_FOUND) {
			log_info("windowsaio: cache invalidation of %s failed: error %lu\n",
				 f->file_name, error);
			rc = 1;
		}
	}

	return rc;
}

static int fio_windowsaio_open_file(struct thread_data *td, struct fio_file *f)
{
	int rc = 0;
	DWORD flags = FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_OVERLAPPED;
	DWORD sharemode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	DWORD openmode = OPEN_ALWAYS;
	DWORD access;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (f->filetype == FIO_TYPE_PIPE) {
		log_err("windowsaio: pipes are not supported\n");
		return 1;
	}

	if (!strcmp(f->file_name, "-")) {
		log_err("windowsaio: can't read/write to stdin/out\n");
		return 1;
	}

	if (td->o.odirect)
		flags |= FILE_FLAG_NO_BUFFERING;
	if (td->o.sync_io)
		flags |= FILE_FLAG_WRITE_THROUGH;

	/*
	 * Inform Windows whether we're going to be doing sequential or
	 * random IO so it can tune the Cache Manager
	 */
	switch (td->o.fadvise_hint) {
	case F_ADV_TYPE:
		if (td_random(td))
			flags |= FILE_FLAG_RANDOM_ACCESS;
		else
			flags |= FILE_FLAG_SEQUENTIAL_SCAN;
		break;
	case F_ADV_RANDOM:
		flags |= FILE_FLAG_RANDOM_ACCESS;
		break;
	case F_ADV_SEQUENTIAL:
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;
		break;
	case F_ADV_NONE:
		break;
	default:
		log_err("fio: unknown fadvise type %d\n", td->o.fadvise_hint);
	}

	if ((!td_write(td) && !(td->flags & TD_F_SYNCS)) || read_only)
		access = GENERIC_READ;
	else
		access = (GENERIC_READ | GENERIC_WRITE);

	if (td->o.create_on_open)
		openmode = OPEN_ALWAYS;
	else
		openmode = OPEN_EXISTING;

	/* If we're going to use direct I/O, Windows will try and invalidate
	 * its cache at that point so there's no need to do it here */
	if (td->o.invalidate_cache && !td->o.odirect)
		windowsaio_invalidate_cache(f);

	f->hFile = CreateFile(f->file_name, access, sharemode,
		NULL, openmode, flags, NULL);

	if (f->hFile == INVALID_HANDLE_VALUE) {
		log_err("windowsaio: failed to open file \"%s\"\n", f->file_name);
		rc = 1;
	}

	/* Only set up the completion port and thread if we're not just
	 * querying the device size */
	if (!rc && td->io_ops_data != NULL) {
		struct windowsaio_data *wd;

		wd = td->io_ops_data;

		if (CreateIoCompletionPort(f->hFile, wd->iocp, 0, 0) == NULL) {
			log_err("windowsaio: failed to create io completion port\n");
			rc = 1;
		}
	}

	return rc;
}

static int fio_windowsaio_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	int rc = 0;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (f->hFile != INVALID_HANDLE_VALUE) {
		if (!CloseHandle(f->hFile)) {
			log_info("windowsaio: failed to close file handle for \"%s\"\n", f->file_name);
			rc = 1;
		}
	}

	f->hFile = INVALID_HANDLE_VALUE;
	return rc;
}

static BOOL timeout_expired(DWORD start_count, DWORD end_count)
{
	BOOL expired = FALSE;
	DWORD current_time;

	current_time = GetTickCount();

	if ((end_count > start_count) && current_time >= end_count)
		expired = TRUE;
	else if (current_time < start_count && current_time > end_count)
		expired = TRUE;

	return expired;
}

static struct io_u* fio_windowsaio_event(struct thread_data *td, int event)
{
	struct windowsaio_data *wd = td->io_ops_data;
	return wd->aio_events[event];
}

/* dequeue completion entrees directly (no separate completion thread) */
static int fio_windowsaio_getevents_nothread(struct thread_data *td, unsigned int min,
				    unsigned int max, const struct timespec *t)
{
	struct windowsaio_data *wd = td->io_ops_data;
	unsigned int dequeued = 0;
	struct io_u *io_u;
	DWORD start_count = 0;
	DWORD end_count = 0;
	DWORD mswait = 250;
	struct fio_overlapped *fov;

	if (t != NULL) {
		mswait = (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
		start_count = GetTickCount();
		end_count = start_count + (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
	}

	do {
		BOOL ret;
		OVERLAPPED *ovl;

		ULONG entries = min(16, max-dequeued);
		OVERLAPPED_ENTRY oe[16];
		ret = GetQueuedCompletionStatusEx(wd->iocp, oe, 16, &entries, mswait, 0);
		if (ret && entries) {
			int entry_num;

			for (entry_num=0; entry_num<entries; entry_num++) {
				ovl = oe[entry_num].lpOverlapped;
				fov = CONTAINING_RECORD(ovl, struct fio_overlapped, o);
				io_u = fov->io_u;

				if (ovl->Internal == ERROR_SUCCESS) {
					io_u->resid = io_u->xfer_buflen - ovl->InternalHigh;
					io_u->error = 0;
				} else {
					io_u->resid = io_u->xfer_buflen;
					io_u->error = win_to_posix_error(GetLastError());
				}

				fov->io_complete = FALSE;
				wd->aio_events[dequeued] = io_u;
				dequeued++;
			}
		}

		if (dequeued >= min ||
			(t != NULL && timeout_expired(start_count, end_count)))
			break;
	} while (1);
	return dequeued;
}

/* dequeue completion entrees creates by separate IoCompletionRoutine thread */
static int fio_windowaio_getevents_thread(struct thread_data *td, unsigned int min,
				    unsigned int max, const struct timespec *t)
{
	struct windowsaio_data *wd = td->io_ops_data;
	unsigned int dequeued = 0;
	struct io_u *io_u;
	int i;
	struct fio_overlapped *fov;
	DWORD start_count = 0;
	DWORD end_count = 0;
	DWORD status;
	DWORD mswait = 250;

	if (t != NULL) {
		mswait = (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
		start_count = GetTickCount();
		end_count = start_count + (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
	}

	do {
		io_u_qiter(&td->io_u_all, io_u, i) {
			if (!(io_u->flags & IO_U_F_FLIGHT))
				continue;

			fov = (struct fio_overlapped*)io_u->engine_data;

			if (fov->io_complete) {
				fov->io_complete = FALSE;
				wd->aio_events[dequeued] = io_u;
				dequeued++;
			}
		}
		if (dequeued >= min)
			break;

		if (dequeued < min) {
			status = WaitForSingleObject(wd->iocomplete_event, mswait);
			if (status != WAIT_OBJECT_0 && dequeued >= min)
				break;
		}

		if (dequeued >= min ||
		    (t != NULL && timeout_expired(start_count, end_count)))
			break;
	} while (1);

	return dequeued;
}

static int fio_windowsaio_getevents(struct thread_data *td, unsigned int min,
				    unsigned int max, const struct timespec *t)
{
	struct windowsaio_options *o = td->eo;

	if (o->no_completion_thread)
		return fio_windowsaio_getevents_nothread(td, min, max, t);
	return fio_windowaio_getevents_thread(td, min, max, t);
}

static enum fio_q_status fio_windowsaio_queue(struct thread_data *td,
					      struct io_u *io_u)
{
	struct fio_overlapped *o = io_u->engine_data;
	LPOVERLAPPED lpOvl = &o->o;
	BOOL success = FALSE;
	int rc = FIO_Q_COMPLETED;

	fio_ro_check(td, io_u);

	lpOvl->Internal = 0;
	lpOvl->InternalHigh = 0;
	lpOvl->Offset = io_u->offset & 0xFFFFFFFF;
	lpOvl->OffsetHigh = io_u->offset >> 32;

	switch (io_u->ddir) {
	case DDIR_WRITE:
		success = WriteFile(io_u->file->hFile, io_u->xfer_buf,
					io_u->xfer_buflen, NULL, lpOvl);
		break;
	case DDIR_READ:
		success = ReadFile(io_u->file->hFile, io_u->xfer_buf,
					io_u->xfer_buflen, NULL, lpOvl);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
		success = FlushFileBuffers(io_u->file->hFile);
		if (!success) {
			log_err("windowsaio: failed to flush file buffers\n");
			io_u->error = win_to_posix_error(GetLastError());
		}

		return FIO_Q_COMPLETED;
	case DDIR_TRIM:
		log_err("windowsaio: manual TRIM isn't supported on Windows\n");
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
		return FIO_Q_COMPLETED;
	default:
		assert(0);
		break;
	}

	if (success || GetLastError() == ERROR_IO_PENDING)
		rc = FIO_Q_QUEUED;
	else {
		io_u->error = win_to_posix_error(GetLastError());
		io_u->resid = io_u->xfer_buflen;
	}

	return rc;
}

/* Runs as a thread and waits for queued IO to complete */
static DWORD WINAPI IoCompletionRoutine(LPVOID lpParameter)
{
	OVERLAPPED *ovl;
	struct fio_overlapped *fov;
	struct io_u *io_u;
	struct windowsaio_data *wd;
	struct thread_ctx *ctx;
	ULONG_PTR ulKey = 0;
	DWORD bytes;

	ctx = (struct thread_ctx*)lpParameter;
	wd = ctx->wd;

	do {
		BOOL ret;

		ret = GetQueuedCompletionStatus(ctx->iocp, &bytes, &ulKey,
						&ovl, 250);
		if (!ret && ovl == NULL)
			continue;

		fov = CONTAINING_RECORD(ovl, struct fio_overlapped, o);
		io_u = fov->io_u;

		if (ovl->Internal == ERROR_SUCCESS) {
			io_u->resid = io_u->xfer_buflen - ovl->InternalHigh;
			io_u->error = 0;
		} else {
			io_u->resid = io_u->xfer_buflen;
			io_u->error = win_to_posix_error(GetLastError());
		}

		fov->io_complete = TRUE;
		SetEvent(wd->iocomplete_event);
	} while (ctx->wd->iothread_running);

	CloseHandle(ctx->iocp);
	free(ctx);
	return 0;
}

static void fio_windowsaio_io_u_free(struct thread_data *td, struct io_u *io_u)
{
	struct fio_overlapped *o = io_u->engine_data;

	if (o) {
		io_u->engine_data = NULL;
		free(o);
	}
}

static int fio_windowsaio_io_u_init(struct thread_data *td, struct io_u *io_u)
{
	struct fio_overlapped *o;

	o = malloc(sizeof(*o));
	o->io_complete = FALSE;
	o->io_u = io_u;
	o->o.hEvent = NULL;
	io_u->engine_data = o;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "windowsaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_windowsaio_init,
	.queue		= fio_windowsaio_queue,
	.getevents	= fio_windowsaio_getevents,
	.event		= fio_windowsaio_event,
	.cleanup	= fio_windowsaio_cleanup,
	.open_file	= fio_windowsaio_open_file,
	.close_file	= fio_windowsaio_close_file,
	.get_file_size	= generic_get_file_size,
	.io_u_init	= fio_windowsaio_io_u_init,
	.io_u_free	= fio_windowsaio_io_u_free,
	.options	= options,
	.option_struct_size	= sizeof(struct windowsaio_options),
};

static void fio_init fio_windowsaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_windowsaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
