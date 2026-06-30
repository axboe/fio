/* Copyright (c) Advanced Micro Devices, Inc. All rights reserved.
 * mailto: hipfile-maintainer@amd.com
 *
 * License: GPLv2, see COPYING.
 *
 * libhipfile engine
 *
 * FIO gpuaccel engine implementation for AMD ROCm hipfile API.
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <hipfile.h>
#include <hip/hip_runtime.h>

#include "../fio.h"
#include "../optgroup.h"
#include "gpuaccel.h"

struct libhipfile_file_data {
	hipFileDescr_t hf_descr;
	hipFileHandle_t hf_handle;
};

static struct fio_option options[] = {
	{
		.name	  = "gpu_dev_ids",
		.lname	  = "libhipfile engine gpu dev ids",
		.type	  = FIO_OPT_STR_STORE,
		.off1	  = offsetof(struct gpuaccel_options, gpu_ids),
		.help	  = "GPU IDs, one per subjob, separated by " GPU_ID_SEP,
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_LIBHIPFILE,
	},
	{
		.name	  = "rocm_io",
		.lname	  = "libhipfile rocm io",
		.type	  = FIO_OPT_STR,
		.off1	  = offsetof(struct gpuaccel_options, io_mode),
		.help	  = "Type of I/O to use with ROCm",
		.def      = "hipfile",
		.posval   = {
			    { .ival = "hipfile",
			      .oval = IO_DIRECT,
			      .help = "libhipfile"
			    },
			    { .ival = "posix",
			      .oval = IO_POSIX,
			      .help = "POSIX I/O"
			    }
		},
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_LIBHIPFILE,
	},
	{
		.name	 = NULL,
	},
};

static const char *fio_libhipfile_get_hip_error(hipFileError_t st)
{
	if (st.err > HIPFILE_BASE_ERR)
		return hipFileGetOpErrorString(st.err);
	return "unknown";
}

static int libhipfile_check_runtime(hipError_t res, const char *fn)
{
	if (res != hipSuccess) {
		const char *str = hipGetErrorName(res);
		log_err("hip runtime api call failed %s : err=%d:%s\n", fn, res, str);
		return -1;
	}

	return 0;
}

static int libhipfile_driver_open(void)
{
	hipFileError_t status = hipFileDriverOpen();

	if (status.err != hipFileSuccess) {
		log_err("hipFileDriverOpen: err=%d:%s\n", status.err,
			fio_libhipfile_get_hip_error(status));
		return -1;
	}

	return 0;
}

static void libhipfile_driver_close(void)
{
	hipFileDriverClose();
}

static int libhipfile_set_device(int gpu_id)
{
	return libhipfile_check_runtime(hipSetDevice(gpu_id), "hipSetDevice");
}

static int libhipfile_malloc(void **mem, size_t size)
{
	return libhipfile_check_runtime(hipMalloc(mem, size), "hipMalloc");
}

static int libhipfile_free(void *mem)
{
	return libhipfile_check_runtime(hipFree(mem), "hipFree");
}

static int libhipfile_memset(void *mem, int value, size_t size)
{
	return libhipfile_check_runtime(hipMemset(mem, value, size), "hipMemset");
}

static int libhipfile_memcpy(void *dst, const void *src, size_t size, int direction)
{
	enum hipMemcpyKind kind;

	switch (direction) {
	case MEMCPY_DIRECTION_H2D:
		kind = hipMemcpyHostToDevice;
		break;
	case MEMCPY_DIRECTION_D2H:
		kind = hipMemcpyDeviceToHost;
		break;
	default:
		return -1;
	}

	return libhipfile_check_runtime(hipMemcpy(dst, src, size, kind), "hipMemcpy");
}

static int libhipfile_stream_sync(void)
{
	return libhipfile_check_runtime(hipStreamSynchronize(NULL),
				       "hipStreamSynchronize");
}

static int libhipfile_file_handle_register(int fd, void **handle)
{
	struct libhipfile_file_data *fhd;
	hipFileError_t status;

	fhd = calloc(1, sizeof(*fhd));
	if (!fhd)
		return ENOMEM;

	fhd->hf_descr.handle.fd = fd;
	fhd->hf_descr.type = hipFileHandleTypeOpaqueFD;
	status = hipFileHandleRegister(&fhd->hf_handle, &fhd->hf_descr);
	if (status.err != hipFileSuccess) {
		log_err("hipFileHandleRegister: err=%d:%s\n", status.err,
			fio_libhipfile_get_hip_error(status));
		free(fhd);
		return EINVAL;
	}

	*handle = fhd;
	return 0;
}

static void libhipfile_file_handle_deregister(void *handle)
{
	struct libhipfile_file_data *fhd = handle;

	hipFileHandleDeregister(fhd->hf_handle);
	free(fhd);
}

static int libhipfile_buf_register(void *mem, size_t size)
{
	hipFileError_t status = hipFileBufRegister(mem, size, 0);

	if (status.err != hipFileSuccess) {
		log_err("hipFileBufRegister: err=%d:%s\n", status.err,
			fio_libhipfile_get_hip_error(status));
		return -1;
	}

	return 0;
}

static void libhipfile_buf_deregister(void *mem)
{
	hipFileBufDeregister(mem);
}

static ssize_t libhipfile_read(void *handle, void *mem, size_t size,
				      unsigned long long file_offset, size_t mem_offset)
{
	struct libhipfile_file_data *fhd = handle;

	return hipFileRead(fhd->hf_handle, mem, size, file_offset, mem_offset);
}

static ssize_t libhipfile_write(void *handle, const void *mem, size_t size,
				       unsigned long long file_offset, size_t mem_offset)
{
	struct libhipfile_file_data *fhd = handle;

	return hipFileWrite(fhd->hf_handle, mem, size, file_offset, mem_offset);
}

static const char *libhipfile_op_error_string(int error_code)
{
	return hipFileGetOpErrorString(error_code);
}

static int running = 0;
static int initialized = 0;
static pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;

static const struct gpuaccel_backend libhipfile_backend = {
	.name = "hipfile",
	.sync_after_posix_write_copy = 1,
	.sync_after_verify_read_copy = 1,
	.sync_after_memset = 1,
	.running = &running,
	.initialized = &initialized,
	.running_lock = &running_lock,
	.driver_open = libhipfile_driver_open,
	.driver_close = libhipfile_driver_close,
	.set_device = libhipfile_set_device,
	.malloc = libhipfile_malloc,
	.free = libhipfile_free,
	.memset = libhipfile_memset,
	.memcpy = libhipfile_memcpy,
	.stream_sync = libhipfile_stream_sync,
	.file_handle_register = libhipfile_file_handle_register,
	.file_handle_deregister = libhipfile_file_handle_deregister,
	.buf_register = libhipfile_buf_register,
	.buf_deregister = libhipfile_buf_deregister,
	.read = libhipfile_read,
	.write = libhipfile_write,
	.op_error_string = libhipfile_op_error_string,
};

static int fio_libhipfile_init(struct thread_data *td)
{
	struct gpuaccel_options *o = td->eo;
	o->backend = &libhipfile_backend;
	return fio_gpuaccel_init(td);
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name               = "libhipfile",
	.version            = FIO_IOOPS_VERSION,
	.init               = fio_libhipfile_init,
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

void fio_init fio_libhipfile_register(void)
{
	register_ioengine(&ioengine);
}

void fio_exit fio_libhipfile_unregister(void)
{
	unregister_ioengine(&ioengine);
}
