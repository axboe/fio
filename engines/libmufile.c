/*
 * License: GPLv2, see COPYING.
 *
 * libmufile engine
 *
 * Synchronous fio backend for Moore Threads libmufile. The queue, buffer
 * lifetime, and GPU id rotation live in gpuaccel.c. This file only adapts
 * the MUSA / muFile calls to struct gpuaccel_backend.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <mufile/mufile_c.h>
#include <musa_runtime.h>

#include "../fio.h"
#include "../optgroup.h"
#include "gpuaccel.h"
#include "libmufile_errno.h"

_Static_assert(MU_FILE_DRIVER_NOT_INITIALIZED == 1,
	"libmufile errno alias assumes error 1");

struct fio_libmufile_data {
	MUFileDescr_t descr;
	MUFileHandle_t fh;
};

static struct fio_option options[] = {
	{
		.name     = "gpu_dev_ids",
		.lname    = "libmufile engine gpu dev ids",
		.type     = FIO_OPT_STR_STORE,
		.off1     = offsetof(struct gpuaccel_options, gpu_ids),
		.help     = "GPU IDs, one per subjob, separated by " GPU_ID_SEP,
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_LIBMUFILE,
	},
	{
		.name     = "musa_io",
		.lname    = "libmufile io mode",
		.type     = FIO_OPT_STR,
		.off1     = offsetof(struct gpuaccel_options, io_mode),
		.help     = "Type of I/O to use with MUSA",
		.def      = "mufile",
		.posval   = {
			{ .ival = "mufile",
			  .oval = IO_DIRECT,
			  .help = "libmufile mtfs path" },
			{ .ival = "posix",
			  .oval = IO_POSIX,
			  .help = "POSIX I/O" },
		},
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_LIBMUFILE,
	},
	{
		.name = NULL,
	},
};

static int libmufile_check_runtime(musaError_t res, const char *fn)
{
	if (res != musaSuccess) {
		log_err("musa runtime api call failed %s : err=%d:%s\n",
			fn, (int)res, musaGetErrorName(res));
		return -1;
	}
	return 0;
}

static const char *libmufile_status_string(MUfileError_t st)
{
	return muFileGetErrorStringC(st);
}

static int libmufile_driver_open(void)
{
	MUfileError_t status = muFileDriverOpen();

	if (status.err != MU_FILE_SUCCESS) {
		log_err("muFileDriverOpen: err=%d:%s\n", status.err,
			libmufile_status_string(status));
		return -1;
	}
	return 0;
}

static void libmufile_driver_close(void)
{
	muFileDriverClose();
}

static int libmufile_set_device(int gpu_id)
{
	return libmufile_check_runtime(musaSetDevice(gpu_id), "musaSetDevice");
}

static int libmufile_malloc(void **mem, size_t size)
{
	return libmufile_check_runtime(musaMalloc(mem, size), "musaMalloc");
}

static int libmufile_free(void *mem)
{
	return libmufile_check_runtime(musaFree(mem), "musaFree");
}

static int libmufile_memset(void *mem, int value, size_t size)
{
	return libmufile_check_runtime(musaMemset(mem, value, size), "musaMemset");
}

static int libmufile_memcpy(void *dst, const void *src, size_t size, int direction)
{
	enum musaMemcpyKind kind;

	switch (direction) {
	case MEMCPY_DIRECTION_H2D:
		kind = musaMemcpyHostToDevice;
		break;
	case MEMCPY_DIRECTION_D2H:
		kind = musaMemcpyDeviceToHost;
		break;
	default:
		return -1;
	}
	return libmufile_check_runtime(musaMemcpy(dst, src, size, kind),
				       "musaMemcpy");
}

static int libmufile_stream_sync(void)
{
	return libmufile_check_runtime(musaStreamSynchronize(NULL),
				       "musaStreamSynchronize");
}

static int libmufile_file_handle_register(int fd, void **handle)
{
	struct fio_libmufile_data *fmd;
	MUfileError_t status;

	fmd = (struct fio_libmufile_data *)calloc(1, sizeof(*fmd));
	if (!fmd)
		return ENOMEM;

	fmd->descr.handle.fd = fd;
	fmd->descr.type = MU_FILE_HANDLE_TYPE_OPAQUE_FD;
	status = muFileHandleRegister(&fmd->fh, &fmd->descr);
	if (status.err != MU_FILE_SUCCESS) {
		log_err("muFileHandleRegister: err=%d:%s\n", status.err,
			libmufile_status_string(status));
		free(fmd);
		return EINVAL;
	}

	*handle = fmd;
	return 0;
}

static void libmufile_file_handle_deregister(void *handle)
{
	struct fio_libmufile_data *fmd = (struct fio_libmufile_data *)handle;

	muFileHandleDeregister(fmd->fh);
	free(fmd);
}

static int libmufile_buf_register(void *mem, size_t size)
{
	MUfileError_t status = muFileBufRegister(mem, size, 0);

	if (status.err != MU_FILE_SUCCESS) {
		log_err("muFileBufRegister: err=%d:%s\n", status.err,
			libmufile_status_string(status));
		return -1;
	}
	return 0;
}

static void libmufile_buf_deregister(void *mem)
{
	muFileBufDeregister(mem);
}

static ssize_t libmufile_read(void *handle, void *mem, size_t size,
			      unsigned long long file_offset, size_t mem_offset)
{
	struct fio_libmufile_data *fmd = (struct fio_libmufile_data *)handle;

	return libmufile_translate_return(
		muFileRead(fmd->fh, mem, size, (off_t)file_offset, (off_t)mem_offset));
}

static ssize_t libmufile_write(void *handle, const void *mem, size_t size,
			       unsigned long long file_offset, size_t mem_offset)
{
	struct fio_libmufile_data *fmd = (struct fio_libmufile_data *)handle;

	return libmufile_translate_return(
		muFileWrite(fmd->fh, (void *)mem, size, (off_t)file_offset, (off_t)mem_offset));
}

static const char *libmufile_op_error_string(int error_code)
{
	MUfileError_t status;

	status.err = libmufile_translate_error_code(error_code);
	return muFileGetErrorStringC(status);
}

static int running;
static int initialized;
static pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;

static const struct gpuaccel_backend libmufile_backend = {
	.name = "mufile",
	.sync_after_posix_write_copy = 0,
	.sync_after_verify_read_copy = 0,
	.sync_after_memset = 0,
	.running = &running,
	.initialized = &initialized,
	.running_lock = &running_lock,
	.driver_open = libmufile_driver_open,
	.driver_close = libmufile_driver_close,
	.set_device = libmufile_set_device,
	.malloc = libmufile_malloc,
	.free = libmufile_free,
	.memset = libmufile_memset,
	.memcpy = libmufile_memcpy,
	.stream_sync = libmufile_stream_sync,
	.file_handle_register = libmufile_file_handle_register,
	.file_handle_deregister = libmufile_file_handle_deregister,
	.buf_register = libmufile_buf_register,
	.buf_deregister = libmufile_buf_deregister,
	.read = libmufile_read,
	.write = libmufile_write,
	.op_error_string = libmufile_op_error_string,
};

static int fio_libmufile_init(struct thread_data *td)
{
	struct gpuaccel_options *o = (struct gpuaccel_options *)td->eo;

	o->backend = &libmufile_backend;
	return fio_gpuaccel_init(td);
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name               = "libmufile",
	.version            = FIO_IOOPS_VERSION,
	.init               = fio_libmufile_init,
	.queue              = fio_gpuaccel_queue,
	.get_file_size      = generic_get_file_size,
	.open_file          = fio_gpuaccel_open_file,
	.close_file         = fio_gpuaccel_close_file,
	.iomem_alloc        = fio_gpuaccel_iomem_alloc,
	.iomem_free         = fio_gpuaccel_iomem_free,
	.cleanup            = fio_gpuaccel_cleanup,
	.flags              = FIO_SYNCIO,
	.options            = options,
	.option_struct_size = sizeof(struct gpuaccel_options),
};

void fio_init fio_libmufile_register(void)
{
	register_ioengine(&ioengine);
}

void fio_exit fio_libmufile_unregister(void)
{
	unregister_ioengine(&ioengine);
}
