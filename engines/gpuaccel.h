#ifndef FIO_GPUACCEL_H
#define FIO_GPUACCEL_H

#include <unistd.h>

#define GPU_ID_SEP ":"

enum fio_q_status;
struct thread_data;
struct io_u;
struct fio_file;

enum {
	IO_DIRECT    = 1,
	IO_POSIX     = 2
};

enum {
	MEMCPY_DIRECTION_H2D = 1,
	MEMCPY_DIRECTION_D2H = 2
};

struct gpuaccel_backend {
	const char *name;
	int (*driver_open)(void);
	void (*driver_close)(void);

	int (*set_device)(int gpu_id);
	int (*malloc)(void **mem, size_t size);
	int (*free)(void *mem);
	int (*memset)(void *mem, int value, size_t size);
	int (*memcpy)(void *dst, const void *src, size_t size, int direction);
	int (*stream_sync)(void);

	int (*file_handle_register)(int fd, void **handle);
	void (*file_handle_deregister)(void *handle);

	int (*buf_register)(void *mem, size_t size);
	void (*buf_deregister)(void *mem);

	ssize_t (*read)(void *handle, void *mem, size_t size,
			      unsigned long long file_offset, size_t mem_offset);
	ssize_t (*write)(void *handle, const void *mem, size_t size,
			       unsigned long long file_offset, size_t mem_offset);

	const char *(*op_error_string)(int error_code);
};

struct gpuaccel_options {
	struct thread_data *td;
	char               *gpu_ids;            /* colon-separated list of GPU ids,
					                           one per job */
	void               *gpu_mem_ptr;        /* GPU memory */
	void               *junk_buf;           /* buffer to simulate cudaMemcpy
					                           with posix I/O write */
	int                 my_gpu_id;          /* GPU id to use for this job */
	unsigned int        io_mode;            /* Type of I/O to use */
	size_t              total_mem;          /* size for gpu_mem_ptr and junk_buf */
	int                 logged;             /* bitmask of log messages that have
					                           been output, prevent flood */
	const struct gpuaccel_backend *backend; /* GPU accelerator backend vtable */
};

int fio_gpuaccel_init(struct thread_data *td);
void fio_gpuaccel_cleanup(struct thread_data *td);
enum fio_q_status fio_gpuaccel_queue(struct thread_data *td, struct io_u *io_u);
int fio_gpuaccel_open_file(struct thread_data *td, struct fio_file *f);
int fio_gpuaccel_close_file(struct thread_data *td, struct fio_file *f);
int fio_gpuaccel_iomem_alloc(struct thread_data *td, size_t total_mem);
void fio_gpuaccel_iomem_free(struct thread_data *td);

#endif
