/*
 * Copyright (c)2020 System Fabric Works, Inc. All Rights Reserved.
 * mailto:info@systemfabricworks.com
 *
 * License: GPLv2, see COPYING.
 *
 * libcufile engine
 *
 * fio I/O engine using the NVIDIA cuFile API.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <cufile.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include <pthread.h>

#include "../fio.h"
#include "../lib/pow2.h"
#include "../optgroup.h"
#include "../lib/memalign.h"
#include "gpuaccel.h"

struct fio_libcufile_data {
	CUfileDescr_t  cf_descr;
	CUfileHandle_t cf_handle;
};

static struct fio_option options[] = {
	{
		.name	  = "gpu_dev_ids",
		.lname	  = "libcufile engine gpu dev ids",
		.type	  = FIO_OPT_STR_STORE,
		.off1	  = offsetof(struct gpuaccel_options, gpu_ids),
		.help	  = "GPU IDs, one per subjob, separated by " GPU_ID_SEP,
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_LIBCUFILE,
	},
	{
		.name	  = "cuda_io",
		.lname	  = "libcufile io mode",
		.type	  = FIO_OPT_STR,
		.off1	  = offsetof(struct gpuaccel_options, io_mode),
		.help	  = "Type of I/O to use with CUDA",
		.def      = "cufile",
		.posval   = {
			    { .ival = "cufile",
			      .oval = IO_DIRECT,
			      .help = "libcufile nvidia-fs"
			    },
			    { .ival = "posix",
			      .oval = IO_POSIX,
			      .help = "POSIX I/O"
			    }
		},
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_LIBCUFILE,
	},
	{
		.name	 = NULL,
	},
};



#define check_cudaruntimecall(fn, rc)                                               \
	do {                                                                        \
		cudaError_t res = fn;                                               \
		if (res != cudaSuccess) {                                           \
			const char *str = cudaGetErrorName(res);                    \
			log_err("cuda runtime api call failed %s:%d : err=%d:%s\n", \
				#fn, __LINE__, res, str);                           \
			rc = -1;                                                    \
		} else                                                              \
			rc = 0;                                                     \
	} while(0)

static const char *fio_libcufile_get_cuda_error(CUfileError_t st)
{
	if (IS_CUFILE_ERR(st.err))
		return cufileop_status_error(st.err);
	return "unknown";
}

static int libcufile_driver_open(void)
{
	CUfileError_t status;

	status = cuFileDriverOpen();
	if (status.err != CU_FILE_SUCCESS) {
		log_err("cuFileDriverOpen: err=%d:%s\n", status.err,
			fio_libcufile_get_cuda_error(status));
		return -1;
	}

	return 0;
}

static void libcufile_driver_close(void)
{
	cuFileDriverClose();
}

static int libcufile_set_device(int gpu_id)
{
	int rc;

	check_cudaruntimecall(cudaSetDevice(gpu_id), rc);
	return rc;
}

static int libcufile_malloc(void **mem, size_t size)
{
	int rc;

	check_cudaruntimecall(cudaMalloc(mem, size), rc);
	return rc;
}

static int libcufile_free(void *mem)
{
	int rc;

	check_cudaruntimecall(cudaFree(mem), rc);
	return rc;
}

static int libcufile_memset(void *mem, int value, size_t size)
{
	int rc;

	check_cudaruntimecall(cudaMemset(mem, value, size), rc);
	return rc;
}

static int libcufile_memcpy(void *dst, const void *src, size_t size, int direction)
{
	int rc;
	enum cudaMemcpyKind kind;

	switch (direction) {
	case MEMCPY_DIRECTION_H2D:
		kind = cudaMemcpyHostToDevice;
		break;
	case MEMCPY_DIRECTION_D2H:
		kind = cudaMemcpyDeviceToHost;
		break;
	default:
		return -1;
	}

	check_cudaruntimecall(cudaMemcpy(dst, src, size, kind), rc);
	return rc;
}

static int libcufile_stream_sync(void)
{
	int rc;

	check_cudaruntimecall(cudaStreamSynchronize(NULL), rc);
	return rc;
}

static int libcufile_file_handle_register(int fd, void **handle)
{
	struct fio_libcufile_data *fcd;
	CUfileError_t status;

	fcd = calloc(1, sizeof(*fcd));
	if (fcd == NULL)
		return ENOMEM;

	fcd->cf_descr.handle.fd = fd;
	fcd->cf_descr.type = CU_FILE_HANDLE_TYPE_OPAQUE_FD;
	status = cuFileHandleRegister(&fcd->cf_handle, &fcd->cf_descr);
	if (status.err != CU_FILE_SUCCESS) {
		log_err("cufile register: err=%d:%s\n", status.err,
			fio_libcufile_get_cuda_error(status));
		free(fcd);
		return EINVAL;
	}

	*handle = fcd;
	return 0;
}

static void libcufile_file_handle_deregister(void *handle)
{
	struct fio_libcufile_data *fcd = handle;

	cuFileHandleDeregister(fcd->cf_handle);
	free(fcd);
}

static int libcufile_buf_register(void *mem, size_t size)
{
	CUfileError_t status;

	status = cuFileBufRegister(mem, size, 0);
	if (status.err != CU_FILE_SUCCESS) {
		log_err("cuFileBufRegister: err=%d:%s\n", status.err,
			fio_libcufile_get_cuda_error(status));
		return -1;
	}

	return 0;
}

static void libcufile_buf_deregister(void *mem)
{
	cuFileBufDeregister(mem);
}

static ssize_t libcufile_read(void *handle, void *mem, size_t size, unsigned long long offset, size_t mem_offset)
{
	struct fio_libcufile_data *fcd = handle;
	return cuFileRead(fcd->cf_handle, mem, size, offset, mem_offset);
}

static ssize_t libcufile_write(void *handle, const void *mem, size_t size, unsigned long long offset, size_t mem_offset)
{
	struct fio_libcufile_data *fcd = handle;
	return cuFileWrite(fcd->cf_handle, mem, size, offset, mem_offset);
}

static const char *libcufile_op_error_string(int error_code)
{
	return cufileop_status_error(error_code);
}

static int running = 0;
static int initialized = 0;
static pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;

static const struct gpuaccel_backend libcufile_backend = {
	.name = "cufile",
	.sync_after_posix_write_copy = 0,
	.sync_after_verify_read_copy = 0,
	.sync_after_memset = 0,
	.running = &running,
	.initialized = &initialized,
	.running_lock = &running_lock,
	.driver_open = libcufile_driver_open,
	.driver_close = libcufile_driver_close,
	.set_device = libcufile_set_device,
	.malloc = libcufile_malloc,
	.free = libcufile_free,
	.memset = libcufile_memset,
	.memcpy = libcufile_memcpy,
	.stream_sync = libcufile_stream_sync,
	.file_handle_register = libcufile_file_handle_register,
	.file_handle_deregister = libcufile_file_handle_deregister,
	.buf_register = libcufile_buf_register,
	.buf_deregister = libcufile_buf_deregister,
	.read = libcufile_read,
	.write = libcufile_write,
	.op_error_string = libcufile_op_error_string
};

static int fio_libcufile_init(struct thread_data *td)
{
	struct gpuaccel_options *o = td->eo;
	o->backend = &libcufile_backend;
	return fio_gpuaccel_init(td);
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name                = "libcufile",
	.version             = FIO_IOOPS_VERSION,
	.init                = fio_libcufile_init,
	.queue               = fio_gpuaccel_queue,
	.get_file_size       = generic_get_file_size,
	.open_file           = fio_gpuaccel_open_file,
	.close_file          = fio_gpuaccel_close_file,
	.iomem_alloc         = fio_gpuaccel_iomem_alloc,
	.iomem_free          = fio_gpuaccel_iomem_free,
	.cleanup             = fio_gpuaccel_cleanup,
	.flags               = FIO_SYNCIO,
	.options             = options,
	.option_struct_size  = sizeof(struct gpuaccel_options)
};

void fio_init fio_libcufile_register(void)
{
	register_ioengine(&ioengine);
}

void fio_exit fio_libcufile_unregister(void)
{
	unregister_ioengine(&ioengine);
}
