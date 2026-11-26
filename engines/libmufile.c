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
	const char *str;

	if (!libmufile_error_code_is_valid(st.err, MU_FILE_MAX_ERROR))
		return "unknown";
	str = muFileGetErrorStringC(st);
	return str ? str : "unknown";
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

/*
 * Round allocation and registration lengths up to 256 KiB. This is fio's
 * length policy. libmufile requires the base and the length to be multiples
 * of the host page size, and it rejects a registration longer than 16 MiB.
 */
#define LIBMUFILE_BUF_ALIGN (256 * 1024)

static size_t libmufile_align_size(size_t size)
{
	return (size + LIBMUFILE_BUF_ALIGN - 1) &
	       ~(size_t)(LIBMUFILE_BUF_ALIGN - 1);
}

static int libmufile_malloc(void **mem, size_t size)
{
	size_t alloc_size = libmufile_align_size(size);

	/*
	 * alloc_size is the byte count. This path does not inspect the
	 * pointer. libmufile requires host-page alignment of the base;
	 * the 256 KiB round-up is fio's length policy.
	 */
	return libmufile_check_runtime(musaMalloc(mem, alloc_size),
				       "musaMalloc");
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

	fmd = calloc(1, sizeof(*fmd));
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
	struct fio_libmufile_data *fmd = handle;

	muFileHandleDeregister(fmd->fh);
	free(fmd);
}

static size_t libmufile_buf_register_size(struct thread_data *td, size_t size)
{
	/*
	 * allocate_io_mem() adds a host-page tail when O_DIRECT or
	 * mem_align is set, and that padded length arrives here as size.
	 * libmufile rejects a length that is not a multiple of the host
	 * page size or is above 16 MiB. On a 16 MiB span the tail exceeds
	 * that limit, and rounding the padded length up to 256 KiB makes
	 * the overshoot larger. The GPU buffer is indexed by io_u, so
	 * register only the maximum read or write block times iodepth.
	 * libmufile_buf_register() then applies fio's 256 KiB round-up.
	 * A 16 MiB span therefore registers as 16 MiB, not 16 MiB plus
	 * the host tail.
	 */
	(void)size;

	return td_max_rw_bs(td) * (size_t)td->o.iodepth;
}

static int libmufile_buf_register(void *mem, size_t size)
{
	MUfileError_t status = muFileBufRegister(mem, libmufile_align_size(size),
						 0);

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
	struct fio_libmufile_data *fmd = handle;

	return libmufile_translate_return(
		muFileRead(fmd->fh, mem, size, (off_t)file_offset, (off_t)mem_offset));
}

static ssize_t libmufile_write(void *handle, const void *mem, size_t size,
			       unsigned long long file_offset, size_t mem_offset)
{
	struct fio_libmufile_data *fmd = handle;

	return libmufile_translate_return(
		muFileWrite(fmd->fh, (void *)mem, size, (off_t)file_offset, (off_t)mem_offset));
}

static const char *libmufile_op_error_string(int error_code)
{
	MUfileError_t status = { 0 };

	status.err = libmufile_translate_error_code(error_code);
	return libmufile_status_string(status);
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
	.buf_register_size = libmufile_buf_register_size,
	.buf_register = libmufile_buf_register,
	.buf_deregister = libmufile_buf_deregister,
	.read = libmufile_read,
	.write = libmufile_write,
	.op_error_string = libmufile_op_error_string,
};

static int fio_libmufile_init(struct thread_data *td)
{
	struct gpuaccel_options *o = td->eo;

	compiletime_assert(MU_FILE_DRIVER_NOT_INITIALIZED == 1,
			   "libmufile errno alias assumes error 1");
	o->backend = &libmufile_backend;
	return fio_gpuaccel_init(td);
}

FIO_STATIC struct ioengine_ops libmufile = {
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
	register_ioengine(&libmufile);
}

void fio_exit fio_libmufile_unregister(void)
{
	unregister_ioengine(&libmufile);
}
