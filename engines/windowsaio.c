/*
 * Native Windows async IO engine
 * Copyright (C) 2011 Bruce Cran <bruce@cran.org.uk>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <windows.h>

#include "../fio.h"

typedef BOOL (WINAPI *CANCELIOEX)(HANDLE hFile, LPOVERLAPPED lpOverlapped);

typedef struct {
 OVERLAPPED o;
 struct io_u *io_u;
} FIO_OVERLAPPED;

struct windowsaio_data {
	HANDLE *io_handles;
	unsigned int io_index;
	FIO_OVERLAPPED *ovls;

	HANDLE iothread;
	HANDLE iothread_stopped;
	BOOL iothread_running;

	struct io_u **aio_events;
	HANDLE iocomplete_event;
	CANCELIOEX pCancelIoEx;
	BOOL useIOCP;
};

struct thread_ctx {
	HANDLE iocp;
	struct windowsaio_data *wd;
};

static void PrintError(LPCSTR lpszFunction);
static int fio_windowsaio_cancel(struct thread_data *td,
			       struct io_u *io_u);
static BOOL TimedOut(DWORD start_count, DWORD end_count);
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

static void PrintError(LPCSTR lpszFunction)
{
	// Retrieve the system error message for the last-error code

	LPSTR lpMsgBuf;
	DWORD dw = GetLastError();

	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dw,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPTSTR)&lpMsgBuf,
		0, NULL );

	log_err("%s - %s", lpszFunction, lpMsgBuf);
	LocalFree(lpMsgBuf);
}

static int fio_windowsaio_cancel(struct thread_data *td,
			       struct io_u *io_u)
{
	int rc = 0;

	struct windowsaio_data *wd = td->io_ops->data;

	/* If we're running on Vista or newer, we can cancel individual IO requests */
	if (wd->pCancelIoEx != NULL) {
		FIO_OVERLAPPED *ovl = io_u->engine_data;
		if (!wd->pCancelIoEx(io_u->file->hFile, &ovl->o))
			rc = 1;
	} else
		rc = 1;

	return rc;
}

static BOOL TimedOut(DWORD start_count, DWORD end_count)
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

static int fio_windowsaio_getevents(struct thread_data *td, unsigned int min,
				    unsigned int max, struct timespec *t)
{
	struct windowsaio_data *wd = td->io_ops->data;
	struct flist_head *entry;
	unsigned int dequeued = 0;
	struct io_u *io_u;
	DWORD start_count = 0, end_count = 0;
	BOOL timedout = FALSE;
	unsigned int mswait = 100;

	if (t != NULL) {
		mswait = (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
		start_count = GetTickCount();
		end_count = start_count + (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
	}

	while (dequeued < min && !timedout) {
		flist_for_each(entry, &td->io_u_busylist) {
			io_u = flist_entry(entry, struct io_u, list);

			if (io_u->seen == 0) {
				io_u->seen = 1;
				wd->aio_events[dequeued] = io_u;
				dequeued++;
			}

			if (dequeued == max)
				break;
		}

		if (dequeued < min)
			WaitForSingleObject(wd->iocomplete_event, mswait);

		if (t != NULL && TimedOut(start_count, end_count))
			timedout = TRUE;
	}

	return dequeued;
}

static struct io_u *fio_windowsaio_event(struct thread_data *td, int event)
{
	struct windowsaio_data *wd = td->io_ops->data;
	return wd->aio_events[event];
}

static int fio_windowsaio_queue(struct thread_data *td,
			      struct io_u *io_u)
{
	struct windowsaio_data *wd;
	LPOVERLAPPED lpOvl;
	DWORD iobytes;
	BOOL success = TRUE;
	int ind;
	int rc;

	fio_ro_check(td, io_u);

	wd = td->io_ops->data;
	ind = wd->io_index;

	ResetEvent(wd->io_handles[ind]);

	if (wd->useIOCP) {
	    lpOvl = &wd->ovls[ind].o;

    	lpOvl->Internal = STATUS_PENDING;
    	lpOvl->InternalHigh = 0;
    	lpOvl->Offset = io_u->offset & 0xFFFFFFFF;
    	lpOvl->OffsetHigh = io_u->offset >> 32;
    	lpOvl->hEvent = wd->io_handles[ind];
    	lpOvl->Pointer = NULL;
    	wd->ovls[ind].io_u = io_u;
	} else {
	    lpOvl = NULL;
    }

	io_u->engine_data = &wd->ovls[ind];
	io_u->seen = 0;

	if (io_u->ddir == DDIR_WRITE) {
		success = WriteFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &iobytes, lpOvl);
	} else if (io_u->ddir == DDIR_READ) {
		success = ReadFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &iobytes, lpOvl);
	} else if (io_u->ddir == DDIR_SYNC     ||
			   io_u->ddir == DDIR_DATASYNC ||
			   io_u->ddir == DDIR_SYNC_FILE_RANGE)
	{
		FlushFileBuffers(io_u->file->hFile);
		return FIO_Q_COMPLETED;
	} else if (io_u->ddir == DDIR_TRIM) {
		log_info("Manual TRIM isn't supported on Windows");
		return FIO_Q_COMPLETED;
	} else
		assert(0);

    if (wd->useIOCP && (success || GetLastError() == ERROR_IO_PENDING)) {
        wd->io_index = (wd->io_index + 1) % td->o.iodepth;
		rc = FIO_Q_QUEUED;
	} else if (success && !wd->useIOCP) {
		io_u->resid = io_u->xfer_buflen - iobytes;
		io_u->error = 0;
		rc = FIO_Q_COMPLETED;
	} else {
		PrintError(__func__);
		io_u->error = GetLastError();
		io_u->resid = io_u->xfer_buflen;
		rc = FIO_Q_COMPLETED;
	}

	return rc;
}

static void fio_windowsaio_cleanup(struct thread_data *td)
{
	int i;
	struct windowsaio_data *wd;

	wd = td->io_ops->data;

	WaitForSingleObject(wd->iothread_stopped, INFINITE);

	if (wd != NULL) {
		CloseHandle(wd->iothread);
		CloseHandle(wd->iothread_stopped);
		CloseHandle(wd->iocomplete_event);

		for (i = 0; i < td->o.iodepth; i++) {
			CloseHandle(wd->io_handles[i]);
		}

		free(wd->aio_events);
		free(wd->io_handles);
		free(wd->ovls);
		free(wd);

		td->io_ops->data = NULL;
	}
}

/* Runs as a thread and waits for queued IO to complete */
static DWORD WINAPI IoCompletionRoutine(LPVOID lpParameter)
{
	OVERLAPPED *ovl;
	FIO_OVERLAPPED *fov;
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

		fov = CONTAINING_RECORD(ovl, FIO_OVERLAPPED, o);
		io_u = fov->io_u;

        /* We sometimes get an IO request that hasn't completed yet. Ignore it. */
        if (ovl->Internal == STATUS_PENDING)
            continue;

		if (ovl->Internal == ERROR_SUCCESS) {
			io_u->resid = io_u->xfer_buflen - ovl->InternalHigh;
			io_u->error = 0;
		} else {
			io_u->resid = io_u->xfer_buflen;
			io_u->error = ovl->Internal;
		}

		SetEvent(wd->iocomplete_event);
	} while (ctx->wd->iothread_running);

	CloseHandle(ctx->iocp);
	SetEvent(ctx->wd->iothread_stopped);
	free(ctx);

	return 0;
}

static int fio_windowsaio_init(struct thread_data *td)
{
	struct windowsaio_data *wd;
	HANDLE hKernel32Dll;
	int rc = 0;

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
		wd->io_handles = malloc(td->o.iodepth * sizeof(HANDLE));
		if (wd->io_handles == NULL)
			rc = 1;
	}

	if (!rc) {
		wd->ovls = malloc(td->o.iodepth * sizeof(FIO_OVERLAPPED));
		if (wd->ovls == NULL)
			rc = 1;
	}

	if (!rc) {
		/* Create an auto-reset event */
		wd->iocomplete_event = CreateEvent(NULL, FALSE, FALSE, NULL);
		if (wd->iocomplete_event == NULL)
			rc = 1;
	}

	if (rc) {
		PrintError(__func__);
		if (wd != NULL) {
			if (wd->ovls != NULL)
				free(wd->ovls);
			if (wd->io_handles != NULL)
				free(wd->io_handles);
			if (wd->aio_events != NULL)
				free(wd->aio_events);

			free(wd);
		}
	}

	hKernel32Dll = GetModuleHandle("kernel32.dll");
	wd->pCancelIoEx = GetProcAddress(hKernel32Dll, "CancelIoEx");

	td->io_ops->data = wd;
	return 0;
}

static int fio_windowsaio_open_file(struct thread_data *td, struct fio_file *f)
{
	int rc = 0;
	HANDLE hFile;
	DWORD flags = FILE_FLAG_POSIX_SEMANTICS;
	DWORD sharemode = FILE_SHARE_READ | FILE_SHARE_WRITE;
	DWORD openmode = OPEN_ALWAYS;
	DWORD access;
	int i;

	dprint(FD_FILE, "fd open %s\n", f->file_name);

	if (f->filetype == FIO_TYPE_PIPE) {
		log_err("fio: windowsaio doesn't support pipes\n");
		return 1;
	}

	if (!strcmp(f->file_name, "-")) {
		log_err("fio: can't read/write to stdin/out\n");
		return 1;
	}

    if (!td->o.odirect && !td->o.sync_io && td->io_ops->data != NULL)
	    flags |= FILE_FLAG_OVERLAPPED;

	if (td->o.odirect)
		flags |= FILE_FLAG_NO_BUFFERING;
	if (td->o.sync_io)
		flags |= FILE_FLAG_WRITE_THROUGH;


	if (td->o.td_ddir == TD_DDIR_READ  ||
		td->o.td_ddir == TD_DDIR_WRITE)
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;
	else
		flags |= FILE_FLAG_RANDOM_ACCESS;

	if (!td_write(td) || read_only)
		access = GENERIC_READ;
	else
		access = (GENERIC_READ | GENERIC_WRITE);

	if (td->o.create_on_open > 0)
		openmode = OPEN_ALWAYS;
	else
		openmode = OPEN_EXISTING;

	f->hFile = CreateFile(f->file_name, access, sharemode,
		NULL, openmode, flags, NULL);

	if (f->hFile == INVALID_HANDLE_VALUE) {
		PrintError(__func__);
		rc = 1;
	}

	/* Only set up the competion port and thread if we're not just
	 * querying the device size */
    if (!rc && td->io_ops->data != NULL && !td->o.odirect && !td->o.sync_io) {
		struct thread_ctx *ctx;
        struct windowsaio_data *wd;
		hFile = CreateIoCompletionPort(f->hFile, NULL, 0, 0);


        wd = td->io_ops->data;

        if (!td->o.odirect && !td->o.sync_io)
            wd->useIOCP = 1;
        else
            wd->useIOCP = 0;

		wd->io_index = 0;
		wd->iothread_running = TRUE;
		/* Create a manual-reset event */
		wd->iothread_stopped = CreateEvent(NULL, TRUE, FALSE, NULL);

		if (wd->iothread_stopped == NULL)
			rc = 1;

		if (!rc) {
			for (i = 0; i < td->o.iodepth; i++) {
				/* Create a manual-reset event for putting in OVERLAPPED */
				wd->io_handles[i] = CreateEvent(NULL, TRUE, FALSE, NULL);
				if (wd->io_handles[i] == NULL) {
					PrintError(__func__);
					rc = 1;
					break;
				}
			}
		}

		if (!rc) {
			ctx = malloc(sizeof(struct thread_ctx));
			ctx->iocp = hFile;
			ctx->wd = wd;

			wd->iothread = CreateThread(NULL, 0, IoCompletionRoutine, ctx, 0, NULL);
		}

		if (rc || wd->iothread == NULL) {
			PrintError(__func__);
			rc = 1;
		}
	}

	return rc;
}

static int fio_windowsaio_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	struct windowsaio_data *wd;

	dprint(FD_FILE, "fd close %s\n", f->file_name);

	if (td->io_ops->data != NULL) {
		wd = td->io_ops->data;
		wd->iothread_running = FALSE;
		WaitForSingleObject(wd->iothread_stopped, INFINITE);
	}

	if (f->hFile != INVALID_HANDLE_VALUE) {
		if (!CloseHandle(f->hFile))
			PrintError(__func__);
	}

	f->hFile = INVALID_HANDLE_VALUE;
	return 0;
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
