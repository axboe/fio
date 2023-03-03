/*
 * libblkio engine
 *
 * IO engine using libblkio to access various block I/O interfaces:
 * https://gitlab.com/libblkio/libblkio
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <blkio.h>

#include "../fio.h"
#include "../optgroup.h"
#include "../options.h"
#include "../parse.h"

/* per-process state */
static struct {
	pthread_mutex_t mutex;
	int initted_threads;
	int initted_hipri_threads;
	struct blkio *b;
} proc_state = { PTHREAD_MUTEX_INITIALIZER, 0, 0, NULL };

static void fio_blkio_proc_lock(void) {
	int ret;
	ret = pthread_mutex_lock(&proc_state.mutex);
	assert(ret == 0);
}

static void fio_blkio_proc_unlock(void) {
	int ret;
	ret = pthread_mutex_unlock(&proc_state.mutex);
	assert(ret == 0);
}

/* per-thread state */
struct fio_blkio_data {
	struct blkioq *q;
	int completion_fd; /* may be -1 if not FIO_BLKIO_WAIT_MODE_EVENTFD */

	bool has_mem_region; /* whether mem_region is valid */
	struct blkio_mem_region mem_region; /* only if allocated by libblkio */

	struct iovec *iovecs; /* for vectored requests */
	struct blkio_completion *completions;
};

enum fio_blkio_wait_mode {
	FIO_BLKIO_WAIT_MODE_BLOCK,
	FIO_BLKIO_WAIT_MODE_EVENTFD,
	FIO_BLKIO_WAIT_MODE_LOOP,
};

struct fio_blkio_options {
	void *pad; /* option fields must not have offset 0 */

	char *driver;

	char *path;
	char *pre_connect_props;

	int num_entries;
	int queue_size;
	char *pre_start_props;

	unsigned int hipri;
	unsigned int vectored;
	unsigned int write_zeroes_on_trim;
	enum fio_blkio_wait_mode wait_mode;
	unsigned int force_enable_completion_eventfd;
};

static struct fio_option options[] = {
	{
		.name	= "libblkio_driver",
		.lname	= "libblkio driver name",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_blkio_options, driver),
		.help	= "Name of the driver to be used by libblkio",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_path",
		.lname	= "libblkio \"path\" property",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_blkio_options, path),
		.help	= "Value to set the \"path\" property to",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_pre_connect_props",
		.lname	= "Additional properties to be set before blkio_connect()",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_blkio_options, pre_connect_props),
		.help	= "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_num_entries",
		.lname	= "libblkio \"num-entries\" property",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct fio_blkio_options, num_entries),
		.help	= "Value to set the \"num-entries\" property to",
		.minval	= 1,
		.interval = 1,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_queue_size",
		.lname	= "libblkio \"queue-size\" property",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct fio_blkio_options, queue_size),
		.help	= "Value to set the \"queue-size\" property to",
		.minval	= 1,
		.interval = 1,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_pre_start_props",
		.lname	= "Additional properties to be set before blkio_start()",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct fio_blkio_options, pre_start_props),
		.help	= "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "hipri",
		.lname	= "Use poll queues",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct fio_blkio_options, hipri),
		.help	= "Use poll queues",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_vectored",
		.lname	= "Use blkioq_{readv,writev}()",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct fio_blkio_options, vectored),
		.help	= "Use blkioq_{readv,writev}() instead of blkioq_{read,write}()",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_write_zeroes_on_trim",
		.lname	= "Use blkioq_write_zeroes() for TRIM",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct fio_blkio_options,
				   write_zeroes_on_trim),
		.help	= "Use blkioq_write_zeroes() for TRIM instead of blkioq_discard()",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_wait_mode",
		.lname	= "How to wait for completions",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct fio_blkio_options, wait_mode),
		.help	= "How to wait for completions",
		.def	= "block",
		.posval = {
			  { .ival = "block",
			    .oval = FIO_BLKIO_WAIT_MODE_BLOCK,
			    .help = "Blocking blkioq_do_io()",
			  },
			  { .ival = "eventfd",
			    .oval = FIO_BLKIO_WAIT_MODE_EVENTFD,
			    .help = "Blocking read() on the completion eventfd",
			  },
			  { .ival = "loop",
			    .oval = FIO_BLKIO_WAIT_MODE_LOOP,
			    .help = "Busy loop with non-blocking blkioq_do_io()",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name	= "libblkio_force_enable_completion_eventfd",
		.lname	= "Force enable the completion eventfd, even if unused",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct fio_blkio_options,
				   force_enable_completion_eventfd),
		.help	= "This can impact performance",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBBLKIO,
	},
	{
		.name = NULL,
	},
};

static int fio_blkio_set_props_from_str(struct blkio *b, const char *opt_name,
					const char *str) {
	int ret = 0;
	char *new_str, *name, *value;

	if (!str)
		return 0;

	/* iteration can mutate string, so copy it */
	new_str = strdup(str);
	if (!new_str) {
		log_err("fio: strdup() failed\n");
		return 1;
	}

	/* iterate over property name-value pairs */
	while ((name = get_next_str(&new_str))) {
		/* split into property name and value */
		value = strchr(name, '=');
		if (!value) {
			log_err("fio: missing '=' in option %s\n", opt_name);
			ret = 1;
			break;
		}

		*value = '\0';
		++value;

		/* strip whitespace from property name */
		strip_blank_front(&name);
		strip_blank_end(name);

		if (name[0] == '\0') {
			log_err("fio: empty property name in option %s\n",
				opt_name);
			ret = 1;
			break;
		}

		/* strip whitespace from property value */
		strip_blank_front(&value);
		strip_blank_end(value);

		/* set property */
		if (blkio_set_str(b, name, value) != 0) {
			log_err("fio: error setting property '%s' to '%s': %s\n",
				name, value, blkio_get_error_msg());
			ret = 1;
			break;
		}
	}

	free(new_str);
	return ret;
}

/*
 * Log the failure of a libblkio function.
 *
 * `(void)func` is to ensure `func` exists and prevent typos
 */
#define fio_blkio_log_err(func) \
	({ \
		(void)func; \
		log_err("fio: %s() failed: %s\n", #func, \
			blkio_get_error_msg()); \
	})

static bool possibly_null_strs_equal(const char *a, const char *b)
{
	return (!a && !b) || (a && b && strcmp(a, b) == 0);
}

/*
 * Returns the total number of subjobs using the 'libblkio' ioengine and setting
 * the 'thread' option in the entire workload that have the given value for the
 * 'hipri' option.
 */
static int total_threaded_subjobs(bool hipri)
{
	int count = 0;

	for_each_td(td) {
		const struct fio_blkio_options *options = td->eo;
		if (strcmp(td->o.ioengine, "libblkio") == 0 &&
		    td->o.use_thread && (bool)options->hipri == hipri)
			++count;
	} end_for_each();

	return count;
}

static struct {
	bool set_up;
	bool direct;
	struct fio_blkio_options opts;
} first_threaded_subjob = { 0 };

static void fio_blkio_log_opt_compat_err(const char *option_name)
{
	log_err("fio: jobs using engine libblkio and sharing a process must agree on the %s option\n",
		option_name);
}

/*
 * If td represents a subjob with option 'thread', check if its options are
 * compatible with those of other threaded subjobs that were already set up.
 */
static int fio_blkio_check_opt_compat(struct thread_data *td)
{
	const struct fio_blkio_options *options = td->eo, *prev_options;

	if (!td->o.use_thread)
		return 0; /* subjob doesn't use 'thread' */

	if (!first_threaded_subjob.set_up) {
		/* first subjob using 'thread', store options for later */
		first_threaded_subjob.set_up	= true;
		first_threaded_subjob.direct	= td->o.odirect;
		first_threaded_subjob.opts	= *options;
		return 0;
	}

	/* not first subjob using 'thread', check option compatibility */
	prev_options = &first_threaded_subjob.opts;

	if (td->o.odirect != first_threaded_subjob.direct) {
		fio_blkio_log_opt_compat_err("direct/buffered");
		return 1;
	}

	if (strcmp(options->driver, prev_options->driver) != 0) {
		fio_blkio_log_opt_compat_err("libblkio_driver");
		return 1;
	}

	if (!possibly_null_strs_equal(options->path, prev_options->path)) {
		fio_blkio_log_opt_compat_err("libblkio_path");
		return 1;
	}

	if (!possibly_null_strs_equal(options->pre_connect_props,
				      prev_options->pre_connect_props)) {
		fio_blkio_log_opt_compat_err("libblkio_pre_connect_props");
		return 1;
	}

	if (options->num_entries != prev_options->num_entries) {
		fio_blkio_log_opt_compat_err("libblkio_num_entries");
		return 1;
	}

	if (options->queue_size != prev_options->queue_size) {
		fio_blkio_log_opt_compat_err("libblkio_queue_size");
		return 1;
	}

	if (!possibly_null_strs_equal(options->pre_start_props,
				      prev_options->pre_start_props)) {
		fio_blkio_log_opt_compat_err("libblkio_pre_start_props");
		return 1;
	}

	return 0;
}

static int fio_blkio_create_and_connect(struct thread_data *td,
					struct blkio **out_blkio)
{
	const struct fio_blkio_options *options = td->eo;
	struct blkio *b;
	int ret;

	if (!options->driver) {
		log_err("fio: engine libblkio requires option libblkio_driver to be set\n");
		return 1;
	}

	if (blkio_create(options->driver, &b) != 0) {
		fio_blkio_log_err(blkio_create);
		return 1;
	}

	/* don't fail if driver doesn't have a "direct" property */
	ret = blkio_set_bool(b, "direct", td->o.odirect);
	if (ret != 0 && ret != -ENOENT) {
		fio_blkio_log_err(blkio_set_bool);
		goto err_blkio_destroy;
	}

	if (blkio_set_bool(b, "read-only", read_only) != 0) {
		fio_blkio_log_err(blkio_set_bool);
		goto err_blkio_destroy;
	}

	if (options->path) {
		if (blkio_set_str(b, "path", options->path) != 0) {
			fio_blkio_log_err(blkio_set_str);
			goto err_blkio_destroy;
		}
	}

	if (fio_blkio_set_props_from_str(b, "libblkio_pre_connect_props",
					 options->pre_connect_props) != 0)
		goto err_blkio_destroy;

	if (blkio_connect(b) != 0) {
		fio_blkio_log_err(blkio_connect);
		goto err_blkio_destroy;
	}

	if (options->num_entries != 0) {
		if (blkio_set_int(b, "num-entries",
				  options->num_entries) != 0) {
			fio_blkio_log_err(blkio_set_int);
			goto err_blkio_destroy;
		}
	}

	if (options->queue_size != 0) {
		if (blkio_set_int(b, "queue-size", options->queue_size) != 0) {
			fio_blkio_log_err(blkio_set_int);
			goto err_blkio_destroy;
		}
	}

	if (fio_blkio_set_props_from_str(b, "libblkio_pre_start_props",
					 options->pre_start_props) != 0)
		goto err_blkio_destroy;

	*out_blkio = b;
	return 0;

err_blkio_destroy:
	blkio_destroy(&b);
	return 1;
}

static bool incompatible_threaded_subjob_options = false;

/*
 * This callback determines the device/file size, so it creates and connects a
 * blkio instance. But it is invoked from the main thread in the original fio
 * process, not from the processes in which jobs will actually run. It thus
 * subsequently destroys the blkio, which is recreated in the init() callback.
 */
static int fio_blkio_setup(struct thread_data *td)
{
	const struct fio_blkio_options *options = td->eo;
	struct blkio *b;
	int ret = 0;
	uint64_t capacity;

	assert(td->files_index == 1);

	if (fio_blkio_check_opt_compat(td) != 0) {
		incompatible_threaded_subjob_options = true;
		return 1;
	}

	if (options->hipri &&
		options->wait_mode == FIO_BLKIO_WAIT_MODE_EVENTFD) {
		log_err("fio: option hipri is incompatible with option libblkio_wait_mode=eventfd\n");
		return 1;
	}

	if (options->hipri && options->force_enable_completion_eventfd) {
		log_err("fio: option hipri is incompatible with option libblkio_force_enable_completion_eventfd\n");
		return 1;
	}

	if (fio_blkio_create_and_connect(td, &b) != 0)
		return 1;

	if (blkio_get_uint64(b, "capacity", &capacity) != 0) {
		fio_blkio_log_err(blkio_get_uint64);
		ret = 1;
		goto out_blkio_destroy;
	}

	td->files[0]->real_file_size = capacity;
	fio_file_set_size_known(td->files[0]);

out_blkio_destroy:
	blkio_destroy(&b);
	return ret;
}

static int fio_blkio_init(struct thread_data *td)
{
	const struct fio_blkio_options *options = td->eo;
	struct fio_blkio_data *data;
	int flags;

	if (td->o.use_thread && incompatible_threaded_subjob_options) {
		/*
		 * Different subjobs using option 'thread' specified
		 * incompatible options. We don't know which configuration
		 * should win, so we just fail all such subjobs.
		 */
		return 1;
	}

	/*
	 * Request enqueueing is fast, and it's not possible to know exactly
	 * when a request is submitted, so never report submission latencies.
	 */
	td->o.disable_slat = 1;

	data = calloc(1, sizeof(*data));
	if (!data) {
		log_err("fio: calloc() failed\n");
		return 1;
	}

	data->iovecs = calloc(td->o.iodepth, sizeof(data->iovecs[0]));
	data->completions = calloc(td->o.iodepth, sizeof(data->completions[0]));
	if (!data->iovecs || !data->completions) {
		log_err("fio: calloc() failed\n");
		goto err_free;
	}

	fio_blkio_proc_lock();

	if (proc_state.initted_threads == 0) {
		/* initialize per-process blkio */
		int num_queues, num_poll_queues;

		if (td->o.use_thread) {
			num_queues 	= total_threaded_subjobs(false);
			num_poll_queues = total_threaded_subjobs(true);
		} else {
			num_queues 	= options->hipri ? 0 : 1;
			num_poll_queues = options->hipri ? 1 : 0;
		}

		if (fio_blkio_create_and_connect(td, &proc_state.b) != 0)
			goto err_unlock;

		if (blkio_set_int(proc_state.b, "num-queues",
				  num_queues) != 0) {
			fio_blkio_log_err(blkio_set_int);
			goto err_blkio_destroy;
		}

		if (blkio_set_int(proc_state.b, "num-poll-queues",
				  num_poll_queues) != 0) {
			fio_blkio_log_err(blkio_set_int);
			goto err_blkio_destroy;
		}

		if (blkio_start(proc_state.b) != 0) {
			fio_blkio_log_err(blkio_start);
			goto err_blkio_destroy;
		}
	}

	if (options->hipri) {
		int i = proc_state.initted_hipri_threads;
		data->q = blkio_get_poll_queue(proc_state.b, i);
	} else {
		int i = proc_state.initted_threads -
				proc_state.initted_hipri_threads;
		data->q = blkio_get_queue(proc_state.b, i);
	}

	if (options->wait_mode == FIO_BLKIO_WAIT_MODE_EVENTFD ||
		options->force_enable_completion_eventfd) {
		/* enable completion fd and make it blocking */
		blkioq_set_completion_fd_enabled(data->q, true);
		data->completion_fd = blkioq_get_completion_fd(data->q);

		flags = fcntl(data->completion_fd, F_GETFL);
		if (flags < 0) {
			log_err("fio: fcntl(F_GETFL) failed: %s\n",
				strerror(errno));
			goto err_blkio_destroy;
		}

		if (fcntl(data->completion_fd, F_SETFL,
			  flags & ~O_NONBLOCK) != 0) {
			log_err("fio: fcntl(F_SETFL) failed: %s\n",
				strerror(errno));
			goto err_blkio_destroy;
		}
	} else {
		data->completion_fd = -1;
	}

	++proc_state.initted_threads;
	if (options->hipri)
		++proc_state.initted_hipri_threads;

	/* Set data last so cleanup() does nothing if init() fails. */
	td->io_ops_data = data;

	fio_blkio_proc_unlock();

	return 0;

err_blkio_destroy:
	if (proc_state.initted_threads == 0)
		blkio_destroy(&proc_state.b);
err_unlock:
	if (proc_state.initted_threads == 0)
		proc_state.b = NULL;
	fio_blkio_proc_unlock();
err_free:
	free(data->completions);
	free(data->iovecs);
	free(data);
	return 1;
}

static int fio_blkio_post_init(struct thread_data *td)
{
	struct fio_blkio_data *data = td->io_ops_data;

	if (!data->has_mem_region) {
		/*
		 * Memory was allocated by the fio core and not iomem_alloc(),
		 * so we need to register it as a memory region here.
		 *
		 * `td->orig_buffer_size` is computed like `len` below, but then
		 * fio can add some padding to it to make sure it is
		 * sufficiently aligned to the page size and the mem_align
		 * option. However, this can make it become unaligned to the
		 * "mem-region-alignment" property in ways that the user can't
		 * control, so we essentially recompute `td->orig_buffer_size`
		 * here but without adding that padding.
		 */

		unsigned long long max_block_size;
		struct blkio_mem_region region;

		max_block_size = max(td->o.max_bs[DDIR_READ],
				     max(td->o.max_bs[DDIR_WRITE],
					 td->o.max_bs[DDIR_TRIM]));

		region = (struct blkio_mem_region) {
			.addr	= td->orig_buffer,
			.len	= (size_t)max_block_size *
					(size_t)td->o.iodepth,
			.fd	= -1,
		};

		if (blkio_map_mem_region(proc_state.b, &region) != 0) {
			fio_blkio_log_err(blkio_map_mem_region);
			return 1;
		}
	}

	return 0;
}

static void fio_blkio_cleanup(struct thread_data *td)
{
	struct fio_blkio_data *data = td->io_ops_data;

	/*
	 * Subjobs from different jobs can be terminated at different times, so
	 * this callback may be invoked for one subjob while another is still
	 * doing I/O. Those subjobs may share the process, so we must wait until
	 * the last subjob in the process wants to clean up to actually destroy
	 * the blkio.
	 */

	if (data) {
		free(data->completions);
		free(data->iovecs);
		free(data);

		fio_blkio_proc_lock();
		if (--proc_state.initted_threads == 0) {
			blkio_destroy(&proc_state.b);
			proc_state.b = NULL;
		}
		fio_blkio_proc_unlock();
	}
}

#define align_up(x, y) ((((x) + (y) - 1) / (y)) * (y))

static int fio_blkio_iomem_alloc(struct thread_data *td, size_t size)
{
	struct fio_blkio_data *data = td->io_ops_data;
	int ret;
	uint64_t mem_region_alignment;

	if (blkio_get_uint64(proc_state.b, "mem-region-alignment",
			     &mem_region_alignment) != 0) {
		fio_blkio_log_err(blkio_get_uint64);
		return 1;
	}

	/* round up size to satisfy mem-region-alignment */
	size = align_up(size, (size_t)mem_region_alignment);

	fio_blkio_proc_lock();

	if (blkio_alloc_mem_region(proc_state.b, &data->mem_region,
				   size) != 0) {
		fio_blkio_log_err(blkio_alloc_mem_region);
		ret = 1;
		goto out;
	}

	if (blkio_map_mem_region(proc_state.b, &data->mem_region) != 0) {
		fio_blkio_log_err(blkio_map_mem_region);
		ret = 1;
		goto out_free;
	}

	td->orig_buffer = data->mem_region.addr;
	data->has_mem_region = true;

	ret = 0;
	goto out;

out_free:
	blkio_free_mem_region(proc_state.b, &data->mem_region);
out:
	fio_blkio_proc_unlock();
	return ret;
}

static void fio_blkio_iomem_free(struct thread_data *td)
{
	struct fio_blkio_data *data = td->io_ops_data;

	if (data && data->has_mem_region) {
		fio_blkio_proc_lock();
		blkio_unmap_mem_region(proc_state.b, &data->mem_region);
		blkio_free_mem_region(proc_state.b, &data->mem_region);
		fio_blkio_proc_unlock();

		data->has_mem_region = false;
	}
}

static int fio_blkio_open_file(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static enum fio_q_status fio_blkio_queue(struct thread_data *td,
					 struct io_u *io_u)
{
	const struct fio_blkio_options *options = td->eo;
	struct fio_blkio_data *data = td->io_ops_data;

	fio_ro_check(td, io_u);

	switch (io_u->ddir) {
		case DDIR_READ:
			if (options->vectored) {
				struct iovec *iov = &data->iovecs[io_u->index];
				iov->iov_base = io_u->xfer_buf;
				iov->iov_len = (size_t)io_u->xfer_buflen;

				blkioq_readv(data->q, io_u->offset, iov, 1,
					     io_u, 0);
			} else {
				blkioq_read(data->q, io_u->offset,
					    io_u->xfer_buf,
					    (size_t)io_u->xfer_buflen, io_u, 0);
			}
			break;
		case DDIR_WRITE:
			if (options->vectored) {
				struct iovec *iov = &data->iovecs[io_u->index];
				iov->iov_base = io_u->xfer_buf;
				iov->iov_len = (size_t)io_u->xfer_buflen;

				blkioq_writev(data->q, io_u->offset, iov, 1,
					      io_u, 0);
			} else {
				blkioq_write(data->q, io_u->offset,
					     io_u->xfer_buf,
					     (size_t)io_u->xfer_buflen, io_u,
					     0);
			}
			break;
		case DDIR_TRIM:
			if (options->write_zeroes_on_trim) {
				blkioq_write_zeroes(data->q, io_u->offset,
						    io_u->xfer_buflen, io_u, 0);
			} else {
				blkioq_discard(data->q, io_u->offset,
					       io_u->xfer_buflen, io_u, 0);
			}
		        break;
		case DDIR_SYNC:
		case DDIR_DATASYNC:
			blkioq_flush(data->q, io_u, 0);
			break;
		default:
			io_u->error = ENOTSUP;
			io_u_log_error(td, io_u);
			return FIO_Q_COMPLETED;
	}

	return FIO_Q_QUEUED;
}

static int fio_blkio_getevents(struct thread_data *td, unsigned int min,
			       unsigned int max, const struct timespec *t)
{
	const struct fio_blkio_options *options = td->eo;
	struct fio_blkio_data *data = td->io_ops_data;
	int ret, n;
	uint64_t event;

	switch (options->wait_mode) {
	case FIO_BLKIO_WAIT_MODE_BLOCK:
		n = blkioq_do_io(data->q, data->completions, (int)min, (int)max,
				 NULL);
		if (n < 0) {
			fio_blkio_log_err(blkioq_do_io);
			return -1;
		}
		return n;
	case FIO_BLKIO_WAIT_MODE_EVENTFD:
		n = blkioq_do_io(data->q, data->completions, 0, (int)max, NULL);
		if (n < 0) {
			fio_blkio_log_err(blkioq_do_io);
			return -1;
		}
		while (n < (int)min) {
			ret = read(data->completion_fd, &event, sizeof(event));
			if (ret != sizeof(event)) {
				log_err("fio: read() on the completion fd returned %d\n",
					ret);
				return -1;
			}

			ret = blkioq_do_io(data->q, data->completions + n, 0,
					   (int)max - n, NULL);
			if (ret < 0) {
				fio_blkio_log_err(blkioq_do_io);
				return -1;
			}

			n += ret;
		}
		return n;
	case FIO_BLKIO_WAIT_MODE_LOOP:
		for (n = 0; n < (int)min; ) {
			ret = blkioq_do_io(data->q, data->completions + n, 0,
					   (int)max - n, NULL);
			if (ret < 0) {
				fio_blkio_log_err(blkioq_do_io);
				return -1;
			}

			n += ret;
		}
		return n;
	default:
		return -1;
	}
}

static struct io_u *fio_blkio_event(struct thread_data *td, int event)
{
	struct fio_blkio_data *data = td->io_ops_data;
	struct blkio_completion *completion = &data->completions[event];
	struct io_u *io_u = completion->user_data;

	io_u->error = -completion->ret;

	return io_u;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "libblkio",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO | FIO_NOEXTEND |
				  FIO_NO_OFFLOAD | FIO_SKIPPABLE_IOMEM_ALLOC,

	.setup			= fio_blkio_setup,
	.init			= fio_blkio_init,
	.post_init		= fio_blkio_post_init,
	.cleanup		= fio_blkio_cleanup,

	.iomem_alloc		= fio_blkio_iomem_alloc,
	.iomem_free		= fio_blkio_iomem_free,

	.open_file		= fio_blkio_open_file,

	.queue			= fio_blkio_queue,
	.getevents		= fio_blkio_getevents,
	.event			= fio_blkio_event,

	.options		= options,
	.option_struct_size	= sizeof(struct fio_blkio_options),
};

static void fio_init fio_blkio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_blkio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
