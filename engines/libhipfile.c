/*
 * Copyright (c)2020 System Fabric Works, Inc. All Rights Reserved.
 * mailto:info@systemfabricworks.com
 *
 * License: GPLv2, see COPYING.
 *
 * libcufile engine
 *
 * fio I/O engine using the AMD hipFile API.
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <hipfile.h>
#include <hip/hip_runtime.h>
#include <pthread.h>

#include "../fio.h"
#include "../lib/pow2.h"
#include "../optgroup.h"
#include "../lib/memalign.h"

#define ALIGNED_4KB(v) (((v) & 0x0fff) == 0)

#define LOGGED_BUFLEN_NOT_ALIGNED     0x01
#define LOGGED_GPU_OFFSET_NOT_ALIGNED 0x02
#define GPU_ID_SEP ":"

enum {
	IO_HIPFILE  = 1,
	IO_POSIX = 2
};

struct libhipfile_options {
	struct thread_data *td;
	char               *gpu_ids;       /* colon-separated list of GPU ids,
					      one per job */
	void               *gpu_mem_ptr;   /* GPU memory */
	void               *junk_buf;      /* buffer to simulate hipMemcpy with
					      posix I/O write */
	int                 my_gpu_id;     /* GPU id to use for this job */
	unsigned int        rocm_io;       /* Type of I/O to use with ROCm */
	size_t              total_mem;     /* size for gpu_mem_ptr and junk_buf */
	int                 logged;        /* bitmask of log messages that have
					      been output, prevent flood */
};

struct fio_libhipfile_data {
	hipFileDescr_t  hf_descr;
	hipFileHandle_t hf_handle;
};

static struct fio_option options[] = {
	{
		.name	  = "gpu_dev_ids",
		.lname	  = "libhipfile engine gpu dev ids",
		.type	  = FIO_OPT_STR_STORE,
		.off1	  = offsetof(struct libhipfile_options, gpu_ids),
		.help	  = "GPU IDs, one per subjob, separated by " GPU_ID_SEP,
		.category = FIO_OPT_C_ENGINE,
		.group	  = FIO_OPT_G_LIBHIPFILE,
	},
	{
		.name	  = "rocm_io",
		.lname	  = "libhipfile rocm io",
		.type	  = FIO_OPT_STR,
		.off1	  = offsetof(struct libhipfile_options, rocm_io),
		.help	  = "Type of I/O to use with ROCm",
		.def      = "hipfile",
		.posval   = {
			    { .ival = "hipfile",
			      .oval = IO_HIPFILE,
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

static int running = 0;
static int hipfile_initialized = 0;
static pthread_mutex_t running_lock = PTHREAD_MUTEX_INITIALIZER;

#define check_hipruntimecall(fn, rc)                                               \
	do {                                                                        \
		hipError_t res = fn;                                               \
		if (res != hipSuccess) {                                           \
			const char *str = hipGetErrorName(res);                    \
			log_err("hip runtime api call failed %s:%d : err=%d:%s\n", \
				#fn, __LINE__, res, str);                           \
			rc = -1;                                                    \
		} else                                                              \
			rc = 0;                                                     \
	} while(0)

static const char *fio_libhipfile_get_hip_error(hipFileError_t st)
{
	if (IS_HIPFILE_ERR(st.err))
		return hipFileGetOpErrorString(st.err);
	return "unknown";
}

/*
 * Assign GPU to subjob roundrobin, similar to how multiple
 * entries in 'directory' are handled by fio.
 */
static int fio_libhipfile_find_gpu_id(struct thread_data *td)
{
	struct libhipfile_options *o = td->eo;
	int gpu_id = 0;

	if (o->gpu_ids != NULL) {
		char *gpu_ids, *pos, *cur;
		int i, id_count, gpu_idx;

		for (id_count = 0, cur = o->gpu_ids; cur != NULL; id_count++) {
			cur = strchr(cur, GPU_ID_SEP[0]);
			if (cur != NULL)
				cur++;
		}

		gpu_idx = td->subjob_number % id_count;

		pos = gpu_ids = strdup(o->gpu_ids);
		if (gpu_ids == NULL) {
			log_err("strdup(gpu_ids): err=%d\n", errno);
			return -1;
		}

		i = 0;
		while (pos != NULL && i <= gpu_idx) {
			i++;
			cur = strsep(&pos, GPU_ID_SEP);
		}

		if (cur)
			gpu_id = atoi(cur);

		free(gpu_ids);
	}

	return gpu_id;
}

static int fio_libhipfile_init(struct thread_data *td)
{
	struct libhipfile_options *o = td->eo;
	hipFileError_t status;
	int initialized;
	int rc;

	pthread_mutex_lock(&running_lock);
	if (running == 0) {
		assert(hipfile_initialized == 0);
		if (o->rocm_io == IO_HIPFILE) {
			/* only open the driver if this is the first worker thread */
			status = hipFileDriverOpen();
			if (status.err != hipFileSuccess)
				log_err("hipFileDriverOpen: err=%d:%s\n", status.err,
					fio_libhipfile_get_hip_error(status));
			else
				hipfile_initialized = 1;
		}
	}
	running++;
	initialized = hipfile_initialized;
	pthread_mutex_unlock(&running_lock);

	if (o->rocm_io == IO_HIPFILE && !initialized)
		return 1;

	o->my_gpu_id = fio_libhipfile_find_gpu_id(td);
	if (o->my_gpu_id < 0)
		return 1;

	dprint(FD_MEM, "Subjob %d uses GPU %d\n", td->subjob_number, o->my_gpu_id);
	check_hipruntimecall(hipSetDevice(o->my_gpu_id), rc);
	if (rc != 0)
		return 1;

	return 0;
}

static inline int fio_libhipfile_pre_write(struct thread_data *td,
					  struct libhipfile_options *o,
					  struct io_u *io_u,
					  size_t gpu_offset)
{
	int rc = 0;

	if (o->rocm_io == IO_HIPFILE) {
		if (td->o.verify) {
			/*
			  Data is being verified, copy the io_u buffer to GPU memory.
			  This isn't done in the non-verify case because the data would
			  already be in GPU memory in a normal rocs application.
			*/
			check_hipruntimecall(hipMemcpy(((char*) o->gpu_mem_ptr) + gpu_offset,
							 io_u->xfer_buf,
							 io_u->xfer_buflen,
							 hipMemcpyHostToDevice), rc);
			if (rc != 0) {
				log_err("DDIR_WRITE hipMemcpy H2D failed\n");
				io_u->error = EIO;
			}
		}
	} else if (o->rocm_io == IO_POSIX) {

		/*
		  POSIX I/O is being used, the data has to be copied out of the
		  GPU into a CPU buffer. GPU memory doesn't contain the actual
		  data to write, copy the data to the junk buffer. The purpose
		  of this is to add the overhead of hipMemcpy() that would be
		  present in a POSIX I/O ROCm application.
		*/
		check_hipruntimecall(hipMemcpy(o->junk_buf + gpu_offset,
						 ((char*) o->gpu_mem_ptr) + gpu_offset,
						 io_u->xfer_buflen,
						 hipMemcpyDeviceToHost), rc);
		if (rc != 0) {
			log_err("DDIR_WRITE hipMemcpy D2H failed\n");
			io_u->error = EIO;
		}
		/* A POSIX I/O ROCm application would also have to synchronize the
		 * default stream to ensure that hipMemcpy has completed */
		check_hipruntimecall(hipStreamSynchronize(NULL), rc);
		if (rc != 0) {
			log_err("DDIR_WRITE hipStreamSynchronize failed\n");
			io_u->error = EIO;
		}
	} else {
		log_err("Illegal ROCm IO type: %d\n", o->rocm_io);
		assert(0);
		rc = EINVAL;
	}

	return rc;
}

static inline int fio_libhipfile_post_read(struct thread_data *td,
					  struct libhipfile_options *o,
					  struct io_u *io_u,
					  size_t gpu_offset)
{
	int rc = 0;

	if (o->rocm_io == IO_HIPFILE) {
		if (td->o.verify) {
			/* Copy GPU memory to CPU buffer for verify */
			check_hipruntimecall(hipMemcpy(io_u->xfer_buf,
							 ((char*) o->gpu_mem_ptr) + gpu_offset,
							 io_u->xfer_buflen,
							 hipMemcpyDeviceToHost), rc);
			if (rc != 0) {
				log_err("DDIR_READ hipMemcpy D2H failed\n");
				io_u->error = EIO;
			}
			/* Ensure the copy is complete before verifying */
			check_hipruntimecall(hipStreamSynchronize(NULL), rc);
			if (rc != 0) {
				log_err("DDIR_READ hipStreamSynchronize failed\n");
				io_u->error = EIO;
			}
		}
	} else if (o->rocm_io == IO_POSIX) {
		/* POSIX I/O read, copy the CPU buffer to GPU memory */
		check_hipruntimecall(hipMemcpy(((char*) o->gpu_mem_ptr) + gpu_offset,
						 io_u->xfer_buf,
						 io_u->xfer_buflen,
						 hipMemcpyHostToDevice), rc);
		if (rc != 0) {
			log_err("DDIR_READ hipMemcpy H2D failed\n");
			io_u->error = EIO;
		}
	} else {
		log_err("Illegal ROCm IO type: %d\n", o->rocm_io);
		assert(0);
		rc = EINVAL;
	}

	return rc;
}

static enum fio_q_status fio_libhipfile_queue(struct thread_data *td,
					     struct io_u *io_u)
{
	struct libhipfile_options *o = td->eo;
	struct fio_libhipfile_data *fhd = FILE_ENG_DATA(io_u->file);
	unsigned long long io_offset;
	ssize_t sz;
	ssize_t remaining;
	size_t xfered;
	size_t gpu_offset;
	int rc;

	if (o->rocm_io == IO_HIPFILE && fhd == NULL) {
		io_u->error = EINVAL;
		td_verror(td, EINVAL, "xfer");
		return FIO_Q_COMPLETED;
	}

	fio_ro_check(td, io_u);

	switch(io_u->ddir) {
	case DDIR_SYNC:
		rc = fsync(io_u->file->fd);
		if (rc != 0) {
			io_u->error = errno;
			log_err("fsync: err=%d\n", errno);
		}
		break;

	case DDIR_DATASYNC:
		rc = fdatasync(io_u->file->fd);
		if (rc != 0) {
			io_u->error = errno;
			log_err("fdatasync: err=%d\n", errno);
		}
		break;

	case DDIR_READ:
	case DDIR_WRITE:
		/*
		  There may be a better way to calculate gpu_offset. The intent is
		  that gpu_offset equals the the difference between io_u->xfer_buf and
		  the page-aligned base address for io_u buffers.
		*/
		gpu_offset = io_u->index * io_u->xfer_buflen;
		io_offset = io_u->offset;
		remaining = io_u->xfer_buflen;

		xfered = 0;
		sz = 0;

		assert(gpu_offset + io_u->xfer_buflen <= o->total_mem);

		if (o->rocm_io == IO_HIPFILE) {
			if (!(ALIGNED_4KB(io_u->xfer_buflen) ||
			      (o->logged & LOGGED_BUFLEN_NOT_ALIGNED))) {
				log_err("buflen not 4KB-aligned: %llu\n", io_u->xfer_buflen);
				o->logged |= LOGGED_BUFLEN_NOT_ALIGNED;
			}

			if (!(ALIGNED_4KB(gpu_offset) ||
			      (o->logged & LOGGED_GPU_OFFSET_NOT_ALIGNED))) {
				log_err("gpu_offset not 4KB-aligned: %lu\n", gpu_offset);
				o->logged |= LOGGED_GPU_OFFSET_NOT_ALIGNED;
			}
		}

		if (io_u->ddir == DDIR_WRITE)
			rc = fio_libhipfile_pre_write(td, o, io_u, gpu_offset);

		if (io_u->error != 0)
			break;

		while (remaining > 0) {
			assert(gpu_offset + xfered <= o->total_mem);
			if (io_u->ddir == DDIR_READ) {
				if (o->rocm_io == IO_HIPFILE) {
					sz = hipFileRead(fhd->hf_handle, o->gpu_mem_ptr, remaining,
							io_offset + xfered, gpu_offset + xfered);
					if (sz == -1) {
						io_u->error = errno;
						log_err("hipFileRead: err=%d\n", errno);
					} else if (sz < 0) {
						io_u->error = EIO;
						log_err("hipFileRead: err=%ld:%s\n", sz,
							hipFileGetOpErrorString(-sz));
					}
				} else if (o->rocm_io == IO_POSIX) {
					sz = pread(io_u->file->fd, ((char*) io_u->xfer_buf) + xfered,
						   remaining, io_offset + xfered);
					if (sz < 0) {
						io_u->error = errno;
						log_err("pread: err=%d\n", errno);
					}
				} else {
					log_err("Illegal ROCm IO type: %d\n", o->rocm_io);
					io_u->error = -1;
					assert(0);
				}
			} else if (io_u->ddir == DDIR_WRITE) {
				if (o->rocm_io == IO_HIPFILE) {
					sz = hipFileWrite(fhd->hf_handle, o->gpu_mem_ptr, remaining,
							 io_offset + xfered, gpu_offset + xfered);
					if (sz == -1) {
						io_u->error = errno;
						log_err("hipFileWrite: err=%d\n", errno);
					} else if (sz < 0) {
						io_u->error = EIO;
						log_err("hipFileWrite: err=%ld:%s\n", sz,
							hipFileGetOpErrorString(-sz));
					}
				} else if (o->rocm_io == IO_POSIX) {
					sz = pwrite(io_u->file->fd,
						    ((char*) io_u->xfer_buf) + xfered,
						    remaining, io_offset + xfered);
					if (sz < 0) {
						io_u->error = errno;
						log_err("pwrite: err=%d\n", errno);
					}
				} else {
					log_err("Illegal ROCm IO type: %d\n", o->rocm_io);
					io_u->error = -1;
					assert(0);
				}
			} else {
				log_err("not DDIR_READ or DDIR_WRITE: %d\n", io_u->ddir);
				io_u->error = -1;
				assert(0);
				break;
			}

			if (io_u->error != 0)
				break;

			remaining -= sz;
			xfered += sz;

			if (remaining != 0)
				log_info("Incomplete %s: %ld bytes remaining\n",
					 io_u->ddir == DDIR_READ? "read" : "write", remaining);
		}

		if (io_u->error != 0)
			break;

		if (io_u->ddir == DDIR_READ)
			rc = fio_libhipfile_post_read(td, o, io_u, gpu_offset);
		break;

	default:
		io_u->error = EINVAL;
		break;
	}

	if (io_u->error != 0) {
		log_err("IO failed\n");
		td_verror(td, io_u->error, "xfer");
	}

	return FIO_Q_COMPLETED;
}

static int fio_libhipfile_open_file(struct thread_data *td, struct fio_file *f)
{
	struct libhipfile_options *o = td->eo;
	struct fio_libhipfile_data *fhd = NULL;
	int rc;
	hipFileError_t status;

	rc = generic_open_file(td, f);
	if (rc)
		return rc;

	if (o->rocm_io == IO_HIPFILE) {
		fhd = calloc(1, sizeof(*fhd));
		if (fhd == NULL) {
			rc = ENOMEM;
			goto exit_err;
		}

		fhd->hf_descr.handle.fd = f->fd;
		fhd->hf_descr.type = hipFileHandleTypeOpaqueFD;
		status = hipFileHandleRegister(&fhd->hf_handle, &fhd->hf_descr);
		if (status.err != hipFileSuccess) {
			log_err("hipFileHandleRegister: err=%d:%s\n", status.err,
				fio_libhipfile_get_hip_error(status));
			rc = EINVAL;
			goto exit_err;
		}
	}

	FILE_SET_ENG_DATA(f, fhd);
	return 0;

exit_err:
	if (fhd) {
		free(fhd);
		fhd = NULL;
	}
	if (f) {
		int rc2 = generic_close_file(td, f);
		if (rc2)
			log_err("generic_close_file: err=%d\n", rc2);
	}
	return rc;
}

static int fio_libhipfile_close_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_libhipfile_data *fhd = FILE_ENG_DATA(f);
	int rc;

	if (fhd != NULL) {
		hipFileHandleDeregister(fhd->hf_handle);
		FILE_SET_ENG_DATA(f, NULL);
		free(fhd);
	}

	rc = generic_close_file(td, f);

	return rc;
}

static int fio_libhipfile_iomem_alloc(struct thread_data *td, size_t total_mem)
{
	struct libhipfile_options *o = td->eo;
	int rc;
	hipFileError_t status;

	o->total_mem = total_mem;
	o->logged = 0;
	o->gpu_mem_ptr = NULL;
	o->junk_buf = NULL;
	td->orig_buffer = calloc(1, total_mem);
	if (!td->orig_buffer) {
		log_err("orig_buffer calloc failed: err=%d\n", errno);
		goto exit_error;
	}

	if (o->rocm_io == IO_POSIX) {
		o->junk_buf = calloc(1, total_mem);
		if (o->junk_buf == NULL) {
			log_err("junk_buf calloc failed: err=%d\n", errno);
			goto exit_error;
		}
	}

	dprint(FD_MEM, "Alloc %zu for GPU %d\n", total_mem, o->my_gpu_id);
	check_hipruntimecall(hipMalloc(&o->gpu_mem_ptr, total_mem), rc);
	if (rc != 0)
		goto exit_error;
	check_hipruntimecall(hipMemset(o->gpu_mem_ptr, 0xab, total_mem), rc);
	check_hipruntimecall(hipStreamSynchronize(NULL), rc);
	if (rc != 0)
		goto exit_error;

	if (o->rocm_io == IO_HIPFILE) {
		status = hipFileBufRegister(o->gpu_mem_ptr, total_mem, 0);
		if (status.err != hipFileSuccess) {
			log_err("hipFileBufRegister: err=%d:%s\n", status.err,
				fio_libhipfile_get_hip_error(status));
			goto exit_error;
		}
	}

	return 0;

exit_error:
	if (td->orig_buffer) {
		free(td->orig_buffer);
		td->orig_buffer = NULL;
	}
	if (o->junk_buf) {
		free(o->junk_buf);
		o->junk_buf = NULL;
	}
	if (o->gpu_mem_ptr) {
		hipFree(o->gpu_mem_ptr);
		o->gpu_mem_ptr = NULL;
	}
	return 1;
}

static void fio_libhipfile_iomem_free(struct thread_data *td)
{
	struct libhipfile_options *o = td->eo;

	if (o->junk_buf) {
		free(o->junk_buf);
		o->junk_buf = NULL;
	}
	if (o->gpu_mem_ptr) {
		if (o->rocm_io == IO_HIPFILE)
			hipFileBufDeregister(o->gpu_mem_ptr);
		hipFree(o->gpu_mem_ptr);
		o->gpu_mem_ptr = NULL;
	}
	if (td->orig_buffer) {
		free(td->orig_buffer);
		td->orig_buffer = NULL;
	}
}

static void fio_libhipfile_cleanup(struct thread_data *td)
{
	struct libhipfile_options *o = td->eo;

	pthread_mutex_lock(&running_lock);
	running--;
	assert(running >= 0);
	if (running == 0) {
		/* only close the driver if initialized and
		   this is the last worker thread */
		if (o->rocm_io == IO_HIPFILE && hipfile_initialized)
			hipFileDriverClose();
		hipfile_initialized = 0;
	}
	pthread_mutex_unlock(&running_lock);
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name                = "libhipfile",
	.version             = FIO_IOOPS_VERSION,
	.init                = fio_libhipfile_init,
	.queue               = fio_libhipfile_queue,
	.get_file_size       = generic_get_file_size,
	.open_file           = fio_libhipfile_open_file,
	.close_file          = fio_libhipfile_close_file,
	.iomem_alloc         = fio_libhipfile_iomem_alloc,
	.iomem_free          = fio_libhipfile_iomem_free,
	.cleanup             = fio_libhipfile_cleanup,
	.flags               = FIO_SYNCIO,
	.options             = options,
	.option_struct_size  = sizeof(struct libhipfile_options)
};

void fio_init fio_libhipfile_register(void)
{
	register_ioengine(&ioengine);
}

void fio_exit fio_libhipfile_unregister(void)
{
	unregister_ioengine(&ioengine);
}
