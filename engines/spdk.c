#include "config-host.h"

#ifdef CONFIG_HAVE_SPDK

#include "fio.h"
#include "optgroup.h"
#include "options.h"
#include "os/os.h"
#include "lib/async.h"

#include <spdk/cpuset.h>
#include <spdk/event.h>
#include <spdk/bdev.h>

struct spdk_fio_opts {
	void*			reserved;
	uint32_t		cpu;
	char			*json_conf;
	struct thread_data 	*td;
	struct fio_completion	cmpl;
};

struct spdk_fio_ctrl {
	bool			app_initialized;
	struct spdk_app_opts	app_opts;
	pthread_t		app_thread;
	pthread_mutex_t		app_mutex;
	struct fio_completion	app_cmpl;
	int			app_rc;
	struct spdk_cpuset 	app_cpuset;
	int			app_cpu_idx;
} ctrl = { .app_mutex = PTHREAD_MUTEX_INITIALIZER };

struct spdk_fio_job {
	int			halt;
	struct thread_data	*td;
	struct spdk_cpuset 	cpuset;
	struct fio_completion	cmpl;
	struct spdk_thread	*thread;
	struct spdk_poller	*poller;
	struct spdk_ring	*sq;
	struct spdk_ring	*cq;
};

static void app_lock(void)
{
	if (pthread_mutex_lock(&ctrl.app_mutex)) {
		abort();
	}
}

static void app_unlock(void)
{
	if (pthread_mutex_unlock(&ctrl.app_mutex)) {
		abort();
	}
}

static struct fio_option fio_opts[] = {
	{
		.name           = "spdk_json_conf",
		.lname          = "A JSON configuration file for SPDK bdev setup",
		.type           = FIO_OPT_STR_STORE,
		.off1           = offsetof(struct spdk_fio_opts, json_conf),
		.help           = "A JSON configuration file for SPDK bdev setup",
		.category       = FIO_OPT_C_ENGINE,
		.group          = FIO_OPT_G_INVALID,
	},
	{
		.name		= NULL,
	},
};

static uint32_t prepare_opts_cpu_select(void)
{
	const uint32_t max_cpu = cpus_configured();
	uint32_t selected_cpu = max_cpu;

	while (true) {
		if (spdk_cpuset_get_cpu(&ctrl.app_cpuset, ctrl.app_cpu_idx)) {
			/* CPU selected */
			selected_cpu = ctrl.app_cpu_idx;
		}

		ctrl.app_cpu_idx++;
		if (ctrl.app_cpu_idx >= max_cpu) {
			ctrl.app_cpu_idx = 0;
		}

		if (selected_cpu != max_cpu) {
			break;
		}
	}

	return selected_cpu;
}

static int prepare_opts_cpu_mask(struct thread_data *td)
{
	struct spdk_fio_opts *opts = td->eo;
	int cpu = 0, i = 0, count = fio_cpu_count(&td->o.cpumask);
	int rc = 0;

	if (!fio_option_is_set(&td->o, cpumask)) {
		log_err("SPDK engine requires specifying CPUs (set cpus_allowed)\n");
		return -1;
	}

	app_lock();

	if (spdk_cpuset_count(&ctrl.app_cpuset)) {
		/* Already configured, just select CPU for this job */
		opts->cpu = prepare_opts_cpu_select();
		goto end;
	}

	while (i < count) {
		if (fio_cpu_isset(&td->o.cpumask, cpu)) {
			spdk_cpuset_set_cpu(&ctrl.app_cpuset, cpu, true);
			i++;
		}
		cpu++;
	}
	if (0 == spdk_cpuset_count(&ctrl.app_cpuset)) {
		log_err("SPDK cannot detect CPU cores to work on\n");
		rc = -1;
		goto end;
	}
	opts->cpu = prepare_opts_cpu_select();

end:
	app_unlock();
	return rc;
}

static int prepare_opts_json_conf(struct thread_data *td)
{
	struct spdk_fio_opts *opts = td->eo;
	FILE *file;

	if (!opts->json_conf || !opts->json_conf[0]) {
		log_err("SPDK engine requires configuration JSON file (set spdk_json_conf)\n");
		return -1;
	}

	/* Test if file exist */
	file = fopen(opts->json_conf, "r");
	if (!file) {
		log_err("SPDK engine configuration JSON file does not exist\n");
		return -1;
	}
	fclose(file);

	return 0;
}

static int prepare_opts(struct thread_data *td)
{
	if (!td->o.use_thread) {
		log_err("SPDK engine works in thread mode only (set thread=1)\n");
		return -1;
	}

	if (prepare_opts_cpu_mask(td)) {
		return -1;
	}

	if (prepare_opts_json_conf(td)) {
		return -1;
	}

	return 0;
}

static void app_start_cb(void *ctx)
{
	/* SPDK application started correctly */
	fio_complete(&ctrl.app_cmpl, 0);
}

static void *app_thread_fn(void *ctx)
{
	int rc;

	rc = spdk_app_start(&ctrl.app_opts, app_start_cb, NULL);
	if (rc) {
		log_err("SPDK application start ERROR\n");
		spdk_app_fini();
		fio_complete(&ctrl.app_cmpl, rc);
	} else {
		/* SPDK has been stoped successfully*/
		spdk_app_fini();
		fio_complete(&ctrl.app_cmpl, 0);
	}

	return NULL;
}

static int prepare_app(struct thread_data *td)
{
	struct spdk_fio_opts *fio_opts = td->eo;

	app_lock();

	if (ctrl.app_initialized || ctrl.app_rc) {
		goto end;
	}
	ctrl.app_initialized = true;

	spdk_app_opts_init(&ctrl.app_opts, sizeof(ctrl.app_opts));
	ctrl.app_opts.name = "FIO SPDK Engine";
	ctrl.app_opts.json_config_file = fio_opts->json_conf;
	ctrl.app_opts.reactor_mask = spdk_cpuset_fmt(&ctrl.app_cpuset);
	ctrl.app_opts.disable_signal_handlers = true;

	fio_init_completion(&ctrl.app_cmpl);
	ctrl.app_rc = pthread_create(&ctrl.app_thread, NULL, app_thread_fn, NULL);
	if (ctrl.app_rc) {
		log_err("Cannot create SPDK application thread\n");
		goto end;
	}

	ctrl.app_rc = fio_wait_for_completion(&ctrl.app_cmpl);
	if (ctrl.app_rc) {
		/* An error occurred, wait for the thread */
		pthread_join(ctrl.app_thread, NULL);
	}

end:
	app_unlock();
	return ctrl.app_rc;
}

static void shutdown_app(struct thread_data *td)
{
	app_lock();
	if (ctrl.app_initialized) {
		if (!ctrl.app_rc) {
			fio_init_completion(&ctrl.app_cmpl);
			spdk_app_start_shutdown();
			fio_wait_for_completion(&ctrl.app_cmpl);
		}
		ctrl.app_initialized = 0;
		ctrl.app_rc = -EINVAL;
		pthread_join(ctrl.app_thread, NULL);
	}
	app_unlock();
}


static void prepare_files_cb(void *ctx)
{
	struct spdk_fio_opts *fio_opts = ctx;
	struct thread_data *td = fio_opts->td;
	struct fio_file *f;
	unsigned int i, rc = 0;

	for_each_file(td, f, i) {
		struct spdk_bdev *bdev;

		bdev = spdk_bdev_get_by_name(f->file_name);
		if (!bdev) {
			log_err("Cannot open file %s\n", f->file_name);
			rc = -ENODEV;
			break;
		}

		f->real_file_size = spdk_bdev_get_num_blocks(bdev) *
				    spdk_bdev_get_block_size(bdev);
		f->filetype = FIO_TYPE_BLOCK;
		fio_file_set_size_known(f);
	}

	fio_complete(&fio_opts->cmpl, rc);
}

static int prepare_files(struct thread_data *td)
{
	struct spdk_fio_opts *fio_opts = td->eo;
	int rc;

	fio_init_completion(&fio_opts->cmpl);
	spdk_thread_send_msg(spdk_thread_get_app_thread(), prepare_files_cb, fio_opts);
	rc = fio_wait_for_completion(&fio_opts->cmpl);

	return rc;
}

static int setup(struct thread_data *td)
{
	struct spdk_fio_opts *fio_opts = td->eo;

	fio_opts->td = td;

	if (prepare_opts(td)) {
		goto error;
	}

	if (prepare_app(td)) {
		goto error;
	}

	if (prepare_files(td)) {
		goto error;
	}
	return 0;
error:

	shutdown_app(td);
	return -1;
}

static int poller(void *ctx)
{
	struct spdk_fio_job *job = ctx;

	if (fio_unlikely(job->halt)) {
		spdk_poller_unregister(&job->poller);
		return SPDK_POLLER_IDLE;
	}

	return SPDK_POLLER_IDLE;
}

static void init_thread(void *ctx)
{
	int rc = 0;
	struct spdk_fio_job *job = ctx;
	struct thread_data *td = job->td;

	/* Create submission ring */
	job->sq = spdk_ring_create(SPDK_RING_TYPE_SP_SC, spdk_align64pow2(td->o.iodepth * 2),
				    SPDK_ENV_SOCKET_ID_ANY);
	if (!job->sq) {
		log_err("Cannot create SPDK thread submission ring\n");
		rc = -ENOMEM;
		goto end;
	}

	/* Create completion ring */
	job->cq = spdk_ring_create(SPDK_RING_TYPE_SP_SC, spdk_align64pow2(td->o.iodepth * 2),
				    SPDK_ENV_SOCKET_ID_ANY);
	if (!job->cq) {
		log_err("Cannot create SPDK thread completion ring\n");
		rc = -ENOMEM;
		goto end;
	}

	/* Create the SPDK poller working within the thread */
	job->poller = SPDK_POLLER_REGISTER(poller, job, 0);
	if (!job->poller) {
		goto end;
	}

end:
	if (rc) {
		if (job->sq) {
			spdk_ring_free(job->sq);
			job->sq = NULL;
		}
		if (job->cq) {
			spdk_ring_free(job->cq);
			job->cq = NULL;
		}
	}

	fio_complete(&job->cmpl, rc);
}

static void stop_thread_msg(void *ctx)
{
	struct spdk_fio_job *job = ctx;
	int rc;

	job->halt = 1;
	if (job->poller) {
		rc = spdk_thread_send_msg(job->thread, stop_thread_msg, job);
		if (rc) {
			abort();
		}
	} else {
		spdk_thread_exit(job->thread);
		job->thread = NULL;
		fio_complete(&job->cmpl, 0);
	}
}


static void stop_thread(struct spdk_fio_job *job)
{
	int rc;

	if (job && job->thread) {
		fio_init_completion(&job->cmpl);
		rc = spdk_thread_send_msg(job->thread, stop_thread_msg, job);
		if (rc) {
			abort();
		}

		if (fio_wait_for_completion(&job->cmpl)) {
			abort();
		}

		if (job->sq) {
			spdk_ring_free(job->sq);
			job->sq = NULL;
		}
		if (job->cq) {
			spdk_ring_free(job->cq);
			job->cq = NULL;
		}
	}
}

static int init(struct thread_data *td)
{
	struct spdk_fio_opts *fio_opts = td->eo;
	struct spdk_fio_job *job;
	char thread_name[256] = { '\0' };
	int rc;

	job = calloc(1, sizeof(*job));
	if (!job) {
		log_err("Memory allocation error when initializing SPDK thread\n");
		return -1;
	}
	job->td = td;

	rc = snprintf(thread_name, sizeof(thread_name), "fio_%s/%u", td->o.name, fio_opts->cpu);
	if (rc < 0 || rc >= sizeof(thread_name)) {
		log_err("Cannot format SPDK thread name\n");
		goto error;
	}

	/* Create SPDK thread working on the specific SPDK CPU core */
	spdk_cpuset_set_cpu(&job->cpuset, fio_opts->cpu, true);
	job->thread = spdk_thread_create(thread_name, &job->cpuset);
	if (!job->thread) {
		log_err("Cannot create SPDK thread\n");
		goto error;
	}

	fio_init_completion(&job->cmpl);
	if (spdk_thread_send_msg(job->thread, init_thread, job)) {
		log_err("Cannot start initialization of SPDK thread\n");
		goto error;
	}
	rc = fio_wait_for_completion(&job->cmpl);
	if (rc) {
		goto error;
	}

	td->io_ops_data = job;
	return 0;
error:
	if (job) {
		stop_thread(job);
		free(job);
	}
	return -1;
}

static enum fio_q_status queue(struct thread_data *td, struct io_u *io_u)
{
	io_u->error = -EINVAL;
	return FIO_Q_COMPLETED;
}

static int get_events(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	return 0;
}

static struct io_u *event(struct thread_data *td, int event)
{
	return NULL;
}

static void cleanup(struct thread_data *td)
{
	struct spdk_fio_job *job = td->io_ops_data;

	stop_thread(job);
	shutdown_app(td);
}

static int open_file(struct thread_data *td, struct fio_file *f)
{
	return -1;
}

static int close_file(struct thread_data *td, struct fio_file *f)
{
	return -1;
}

static int iomem_alloc(struct thread_data *td, size_t total_mem)
{
	return -1;
}

static void iomem_free(struct thread_data *td)
{
}

static int io_u_init(struct thread_data *td, struct io_u *io_u)
{
	return -1;
}

static void io_u_free(struct thread_data *td, struct io_u *io_u)
{
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "spdk",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_RAWIO | FIO_NOEXTEND | FIO_NODISKUTIL | FIO_MEMALIGN,

	.setup			= setup,
	.init			= init,
	.queue			= queue,
	.getevents		= get_events,
	.event			= event,
	.cleanup		= cleanup,
	.open_file		= open_file,
	.close_file		= close_file,
	.iomem_alloc		= iomem_alloc,
	.iomem_free		= iomem_free,
	.io_u_init		= io_u_init,
	.io_u_free		= io_u_free,

	.option_struct_size	= sizeof(struct spdk_fio_opts),
	.options		= fio_opts,
};

static void fio_init fio_spdk_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_spdk_unregister(void)
{
	unregister_ioengine(&ioengine);
}

#endif
