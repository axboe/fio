/*
 * Native Windows async IO engine
 * Copyright (C) 2012 Bruce Cran <bruce@cran.org.uk>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <windows.h>

#include "../fio.h"

typedef BOOL (WINAPI *CANCELIOEX)(HANDLE hFile, LPOVERLAPPED lpOverlapped);

struct fio_overlapped {
	OVERLAPPED o;
	struct io_u *io_u;
	BOOL io_complete;
	BOOL io_free;
};

struct windowsaio_data {
	struct fio_overlapped *ovls;
	struct io_u **aio_events;
	HANDLE iothread;
	HANDLE iocomplete_event;
	CANCELIOEX pCancelIoEx;
	BOOL iothread_running;
};

struct thread_ctx {
	HANDLE iocp;
	struct windowsaio_data *wd;
};

static int fio_windowsaio_cancel(struct thread_data *td,
			       struct io_u *io_u);
static BOOL timeout_expired(DWORD start_count, DWORD end_count);
static int fio_windowsaio_getevents(struct thread_data *td, unsigned int min,
				    unsigned int max, struct timespec *t);
static struct io_u *fio_windowsaio_event(struct thread_data *td, int event);
static int fio_windowsaio_queue(struct thread_data *td,
			      struct io_u *io_u);
static void fio_windowsaio_cleanup(struct thread_data *td);
static DWORD WINAPI IoCompletionRoutine(LPVOID lpParameter);
static int fio_windowsaio_init(struct thread_data *td);
static int fio_windowsaio_open_file(struct thread_data *td, struct fio_file *f);
static int fio_windowsaio_close_file(struct thread_data fio_unused *td, struct fio_file *f);

int sync_file_range(int fd, off64_t offset, off64_t nbytes,
			   unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}

static int fio_windowsaio_init(struct thread_data *td)
{
	struct windowsaio_data *wd;
	HANDLE hKernel32Dll;
	int rc = 0;
	int i;

	wd = malloc(sizeof(struct windowsaio_data));
	if (wd != NULL)
		ZeroMemory(wd, sizeof(struct windowsaio_data));
	else
		rc = 1;

	if (!rc) {
		wd->aio_events = malloc(td->o.iodepth * sizeof(struct io_u*));
		if (wd->aio_events == NULL)
			rc = 1;
	}

	if (!rc) {
		wd->ovls = malloc(td->o.iodepth * sizeof(struct fio_overlapped));
		if (wd->ovls == NULL)
			rc = 1;
	}

	if (!rc) {
		for (i = 0; i < td->o.iodepth; i++) {
			wd->ovls[i].io_free = TRUE;
			wd->ovls[i].io_complete = FALSE;

			wd->ovls[i].o.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
			if (wd->ovls[i].o.hEvent == NULL) {
				rc = 1;
				break;
			}
		}
	}

	if (!rc) {
		/* Create an auto-reset event */
		wd->iocomplete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (wd->iocomplete_event == NULL)
			rc = 1;
	}

	if (rc) {
		if (wd != NULL) {
			if (wd->ovls != NULL)
				free(wd->ovls);
			if (wd->aio_events != NULL)
				free(wd->aio_events);

			free(wd);
		}
	}

	hKernel32Dll = GetModuleHandle("kernel32.dll");
	wd->pCancelIoEx = (CANCELIOEX)GetProcAddress(hKernel32Dll, "CancelIoEx");
	td->io_ops->data = wd;

	return rc;
}

static void fio_windowsaio_cleanup(struct thread_data *td)
{
	int i;
	struct windowsaio_data *wd;

	wd = td->io_ops->data;

	if (wd != NULL) {
		wd->iothread_running = FALSE;
		WaitForSingleObject(wd->iothread, INFINITE);

		CloseHandle(wd->iothread);
		CloseHandle(wd->iocomplete_event);

		for (i = 0; i < td->o.iodepth; i++) {
			CloseHandle(wd->ovls[i].o.hEvent);
		}

		free(wd->aio_events);
		free(wd->ovls);
		free(wd);

		td->io_ops->data = NULL;
	}
}


static int fio_windowsaio_open_file(struct thread_data *td, struct fio_file *f)
{
	int rc = 0;
	HANDLE hFile;
	DWORD flags = FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_OVERLAPPED;
	DWORD sharemode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	DWORD openmode = OPEN_ALWAYS;
	DWORD access;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (f->filetype == FIO_TYPE_PIPE) {
		log_err("fio: windowsaio doesn't support pipes\n");
		return 1;
	}

	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

	if (td->o.odirect)
		flags |= FILE_FLAG_NO_BUFFERING;
	if (td->o.sync_io)
		flags |= FILE_FLAG_WRITE_THROUGH;

	/*
	 * Inform Windows whether we're going to be doing sequential or
	 * random io so it can tune the Cache Manager
	 */
	if (td->o.td_ddir == TD_DDIR_READ  ||
		td->o.td_ddir == TD_DDIR_WRITE)
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;
	else
		flags |= FILE_FLAG_RANDOM_ACCESS;

	if (!td_write(td) || read_only)
		access = GENERIC_READ;
	else
		access = (GENERIC_READ | GENERIC_WRITE);

	if (td->o.create_on_open)
		openmode = OPEN_ALWAYS;
	else
		openmode = OPEN_EXISTING;

	f->hFile = CreateFile(f->file_name, access, sharemode,
		NULL, openmode, flags, NULL);

	if (f->hFile == INVALID_HANDLE_VALUE)
		rc = 1;

	/* Only set up the completion port and thread if we're not just
	 * querying the device size */
	if (!rc && td->io_ops->data != NULL) {
		struct thread_ctx *ctx;
		struct windowsaio_data *wd;

		hFile = CreateIoCompletionPort(f->hFile, NULL, 0, 0);

		wd = td->io_ops->data;
		wd->iothread_running = TRUE;

		if (!rc) {
			ctx = malloc(sizeof(struct thread_ctx));
			ctx->iocp = hFile;
			ctx->wd = wd;

			wd->iothread = CreateThread(NULL, 0, IoCompletionRoutine, ctx, 0, NULL);
		}

		if (rc || wd->iothread == NULL)
			rc = 1;
	}

	return rc;
}

static int fio_windowsaio_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	int rc = 0;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (f->hFile != INVALID_HANDLE_VALUE) {
		if (!CloseHandle(f->hFile))
			rc = 1;
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
	struct windowsaio_data *wd = td->io_ops->data;
	return wd->aio_events[event];
}

static int fio_windowsaio_getevents(struct thread_data *td, unsigned int min,
				    unsigned int max, struct timespec *t)
{
	struct windowsaio_data *wd = td->io_ops->data;
	struct flist_head *entry;
	unsigned int dequeued = 0;
	struct io_u *io_u;
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
		flist_for_each(entry, &td->io_u_busylist) {
			io_u = flist_entry(entry, struct io_u, list);
			fov = (struct fio_overlapped*)io_u->engine_data;

			if (fov->io_complete) {
				fov->io_complete = FALSE;
				fov->io_free  = TRUE;
				ResetEvent(fov->o.hEvent);
				wd->aio_events[dequeued] = io_u;
				dequeued++;
			}

			if (dequeued >= min)
				break;
		}

		if (dequeued < min) {
			status = WaitForSingleObject(wd->iocomplete_event, mswait);
			if (status != WAIT_OBJECT_0 && dequeued >= min)
			    break;
		}

		if (dequeued >= min || (t != NULL && timeout_expired(start_count, end_count)))
			break;
	} while (1);

	return dequeued;
}

static int fio_windowsaio_queue(struct thread_data *td, struct io_u *io_u)
{
	LPOVERLAPPED lpOvl = NULL;
	struct windowsaio_data *wd;
	DWORD iobytes;
	BOOL success = FALSE;
	int index;
	int rc = FIO_Q_COMPLETED;

	fio_ro_check(td, io_u);

	wd = td->io_ops->data;

	for (index = 0; index < td->o.iodepth; index++) {
		if (wd->ovls[index].io_free)
			break;
	}

	assert(index < td->o.iodepth);

	wd->ovls[index].io_free = FALSE;
	wd->ovls[index].io_u = io_u;
	lpOvl = &wd->ovls[index].o;
	lpOvl->Internal = STATUS_PENDING;
	lpOvl->InternalHigh = 0;
	lpOvl->Offset = io_u->offset & 0xFFFFFFFF;
	lpOvl->OffsetHigh = io_u->offset >> 32;
	io_u->engine_data = &wd->ovls[index];

	switch (io_u->ddir) {
	case DDIR_WRITE:
		success = WriteFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &iobytes, lpOvl);
		break;
	case DDIR_READ:
		success = ReadFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &iobytes, lpOvl);
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
		success = FlushFileBuffers(io_u->file->hFile);
		if (!success)
		    io_u->error = GetLastError();

		return FIO_Q_COMPLETED;
		break;
	case DDIR_TRIM:
		log_err("manual TRIM isn't supported on Windows");
		io_u->error = 1;
		io_u->resid = io_u->xfer_buflen;
		return FIO_Q_COMPLETED;
		break;
	default:
		assert(0);
		break;
	}

	if (success || GetLastError() == ERROR_IO_PENDING)
		rc = FIO_Q_QUEUED;
	else {
		io_u->error = GetLastError();
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
		if (!GetQueuedCompletionStatus(ctx->iocp, &bytes, &ulKey, &ovl, 250))
			continue;

		fov = CONTAINING_RECORD(ovl, struct fio_overlapped, o);
		io_u = fov->io_u;

		if (ovl->Internal == ERROR_SUCCESS) {
			io_u->resid = io_u->xfer_buflen - ovl->InternalHigh;
			io_u->error = 0;
		} else {
			io_u->resid = io_u->xfer_buflen;
			io_u->error = ovl->Internal;
		}

		fov->io_complete = TRUE;
		SetEvent(wd->iocomplete_event);
	} while (ctx->wd->iothread_running);

	CloseHandle(ctx->iocp);
	free(ctx);
	return 0;
}

static int fio_windowsaio_cancel(struct thread_data *td,
			       struct io_u *io_u)
{
	int rc = 0;

	struct windowsaio_data *wd = td->io_ops->data;

	/* If we're running on Vista or newer, we can cancel individual IO requests */
	if (wd->pCancelIoEx != NULL) {
		struct fio_overlapped *ovl = io_u->engine_data;

		if (!wd->pCancelIoEx(io_u->file->hFile, &ovl->o))
			rc = 1;
	} else
		rc = 1;

	return rc;
}

static struct ioengine_ops ioengine = {
	.name		= "windowsaio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_windowsaio_init,
	.queue		= fio_windowsaio_queue,
	.cancel		= fio_windowsaio_cancel,
	.getevents	= fio_windowsaio_getevents,
	.event		= fio_windowsaio_event,
	.cleanup	= fio_windowsaio_cleanup,
	.open_file	= fio_windowsaio_open_file,
	.close_file	= fio_windowsaio_close_file,
	.get_file_size	= generic_get_file_size
};

static void fio_init fio_posixaio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_posixaio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
