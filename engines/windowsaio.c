/*
 * Native Windows async IO engine
 * Copyright (C) 2010 Bruce Cran <bruce@cran.org.uk>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <windows.h>

#include "../fio.h"

BOOL windowsaio_debug = FALSE;

struct windowsaio_data {
	struct io_u **aio_events;
	HANDLE *busyIoHandles;
	unsigned int busyIo;
	unsigned int ioFinished;
	BOOL running;
	BOOL stopped;
	HANDLE hThread;
};

typedef struct {
 OVERLAPPED o;
 struct io_u *io_u;
} FIO_OVERLAPPED;

struct thread_ctx {
	HANDLE ioCP;
	struct windowsaio_data *wd;
};

static void PrintError(LPCSTR lpszFunction);
static int fio_windowsaio_cancel(struct thread_data *td,
			       struct io_u *io_u);
static BOOL TimedOut(DWORD startCount, DWORD endCount);
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
	BOOL bSuccess;
	int rc = 0;

	bSuccess = CancelIo(io_u->file->hFile);

	if (!bSuccess)
		rc = 1;

	return rc;
}

static BOOL TimedOut(DWORD startCount, DWORD endCount)
{
	BOOL expired = FALSE;
	DWORD currentTime;

	currentTime = GetTickCount();

	if ((endCount > startCount) && currentTime >= endCount)
		expired = TRUE;
	else if (currentTime < startCount && currentTime > endCount)
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
	DWORD startCount = 0, endCount = 0;
	BOOL timedout = FALSE;
	unsigned int r = 0;
	unsigned int waitInMs = 100;

	if (t != NULL) {
		waitInMs = (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
		startCount = GetTickCount();
		endCount = startCount + (t->tv_sec * 1000) + (t->tv_nsec / 1000000);
	}

	while (dequeued < min && !timedout) {
		WaitForMultipleObjects(wd->busyIo, wd->busyIoHandles, FALSE, waitInMs);

		flist_for_each(entry, &td->io_u_busylist) {
			io_u = flist_entry(entry, struct io_u, list);

			if (io_u->seen == 0)
				continue;

			dequeued++;

			wd->ioFinished--;
			wd->aio_events[r] = io_u;
			r++;

			wd->busyIo--;

			if (dequeued == max)
				break;
		}

		if (t != NULL && TimedOut(startCount, endCount))
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
	FIO_OVERLAPPED *fov;
	DWORD ioBytes;
	BOOL bSuccess = TRUE;
	int rc;

	fio_ro_check(td, io_u);

	fov = malloc(sizeof(FIO_OVERLAPPED));
	ZeroMemory(fov, sizeof(FIO_OVERLAPPED));

	struct windowsaio_data *wd = td->io_ops->data;

	io_u->seen = 0;

	fov->o.Offset = io_u->offset & 0xFFFFFFFF;
	fov->o.OffsetHigh = io_u->offset >> 32;
	fov->o.hEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	fov->io_u = io_u;

	if (fov->o.hEvent == NULL) {
		PrintError(__func__);
		return 1;
	}

	if (io_u->ddir == DDIR_WRITE)
		bSuccess = WriteFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &ioBytes, &fov->o);
	else if (io_u->ddir == DDIR_READ)
		bSuccess = ReadFile(io_u->file->hFile, io_u->xfer_buf, io_u->xfer_buflen, &ioBytes, &fov->o);
	else if (io_u->ddir == DDIR_SYNC     ||
			 io_u->ddir == DDIR_DATASYNC ||
			 io_u->ddir == DDIR_SYNC_FILE_RANGE)
	{
		FlushFileBuffers(io_u->file->hFile);
		return FIO_Q_COMPLETED;
	} else if (io_u->ddir == DDIR_TRIM) {
		log_info("explicit TRIM isn't supported on Windows");
		return FIO_Q_COMPLETED;
	}

	if (bSuccess) {
		io_u->seen = 1;
		io_u->resid = io_u->xfer_buflen - fov->o.InternalHigh;
		io_u->error = 0;
		rc = FIO_Q_COMPLETED;
	} else if (!bSuccess && GetLastError() == ERROR_IO_PENDING) {
		wd->busyIoHandles[wd->busyIo++] = fov->o.hEvent;
		rc = FIO_Q_QUEUED;
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
	struct windowsaio_data *wd;

	wd = td->io_ops->data;
	wd->running = FALSE;

	while (wd->stopped == FALSE)
		Sleep(20);

	if (wd != NULL) {
		CloseHandle(wd->hThread);

		free(wd->aio_events);
		free(wd->busyIoHandles);
		free(wd);

		td->io_ops->data = NULL;
	}

}

static DWORD WINAPI IoCompletionRoutine(LPVOID lpParameter)
{
	OVERLAPPED *ovl;
	FIO_OVERLAPPED *fov;
	struct io_u *io_u;
	struct windowsaio_data *wd;

	struct thread_ctx *ctx;
	ULONG_PTR ulKey = 0;
	BOOL bSuccess;
	DWORD bytes;


	ctx = (struct thread_ctx*)lpParameter;
	wd = ctx->wd;
	bSuccess = TRUE;

	while (ctx->wd->running) {
		bSuccess = GetQueuedCompletionStatus(ctx->ioCP, &bytes, &ulKey, &ovl, 100);

		if (!bSuccess) {
			if (GetLastError() == WAIT_TIMEOUT) {
				continue;
			} else {
				PrintError(__func__);
				continue;
			}
		}

		fov = CONTAINING_RECORD(ovl, FIO_OVERLAPPED, o);
		io_u = fov->io_u;

		if (io_u->seen == 1)
			continue;

		ctx->wd->ioFinished++;

		if (ovl->Internal == ERROR_SUCCESS) {
			io_u->resid = io_u->xfer_buflen - ovl->InternalHigh;
			io_u->error = 0;
		} else {
			io_u->resid = io_u->xfer_buflen;
			io_u->error = 1;
		}

		io_u->seen = 1;
		CloseHandle(ovl->hEvent);
		free(ovl);
	}

	bSuccess = CloseHandle(ctx->ioCP);
	if (!bSuccess)
		PrintError(__func__);

	ctx->wd->stopped = TRUE;
	free(ctx);
	return 0;
}

static int fio_windowsaio_init(struct thread_data *td)
{
	struct windowsaio_data *wd;

	wd = malloc(sizeof(struct windowsaio_data));
	if (wd == NULL)
		return 1;

	wd->aio_events = malloc((td->o.iodepth + 1) * sizeof(struct io_u *));
	if (wd->aio_events == NULL) {
		free(wd);
		return 1;
	}

	wd->busyIoHandles = malloc((td->o.iodepth + 1) * sizeof(struct io_u *));
	if (wd->busyIoHandles == NULL) {
		free(wd->aio_events);
		free(wd);
		return 1;
	}

	ZeroMemory(wd->aio_events, (td->o.iodepth + 1) * sizeof(struct io_u *));
	ZeroMemory(wd->busyIoHandles, (td->o.iodepth + 1) * sizeof(struct io_u *));

	wd->busyIo = 0;
	wd->ioFinished = 0;
	wd->running = FALSE;
	wd->stopped = FALSE;
	wd->hThread = FALSE;

	td->io_ops->data = wd;
	return 0;
}

static int fio_windowsaio_open_file(struct thread_data *td, struct fio_file *f)
{
	int rc = 0;
	HANDLE hFile;
	DWORD flags = FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_POSIX_SEMANTICS | FILE_FLAG_OVERLAPPED;
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


	if (td->o.td_ddir == TD_DDIR_READ  ||
		td->o.td_ddir == TD_DDIR_WRITE ||
		td->o.td_ddir == TD_DDIR_RANDRW)
	{
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;
	}
	else
	{
		flags |= FILE_FLAG_RANDOM_ACCESS;
	}

	if (td_read(td) || read_only)
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
		log_err("Failed to open %s\n", f->file_name);
		PrintError(__func__);
		rc = 1;
	}

	/* Only set up the competion port and thread if we're not just
	 * querying the device size */
	if (!rc && td->io_ops->data != NULL) {
		struct windowsaio_data *wd;
		struct thread_ctx *ctx;
		hFile = CreateIoCompletionPort(f->hFile, NULL, 0, 0);

		wd = td->io_ops->data;
		wd->running = TRUE;
		wd->stopped = FALSE;

		ctx = malloc(sizeof(struct thread_ctx));
		ctx->ioCP = hFile;
		ctx->wd = wd;

		wd->hThread = CreateThread(NULL, 0, IoCompletionRoutine, ctx, 0, NULL);

		if (wd->hThread == NULL) {
			PrintError(__func__);
			rc = 1;
		}
	}

	return rc;
}

static int fio_windowsaio_close_file(struct thread_data fio_unused *td, struct fio_file *f)
{
	BOOL bSuccess;

	if (f->hFile != INVALID_HANDLE_VALUE) {
		bSuccess = CloseHandle(f->hFile);
		if (!bSuccess)
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
