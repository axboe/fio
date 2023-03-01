#include "config-host.h"

#ifdef CONFIG_HAVE_SPDK

#include "fio.h"
#include "optgroup.h"
#include "options.h"
#include "os/os.h"

#include <spdk/cpuset.h>

struct spdk_fio_opts {
	const char *cpu_mask;
	char *json_conf;
};

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

static int prepare_opts_cpu_mask(struct thread_data *td)
{
	struct spdk_fio_opts *opts = td->eo;
	struct spdk_cpuset cpuset = {};
	int cpu = 0, i = 0, count = fio_cpu_count(&td->o.cpumask);

	if (!fio_option_is_set(&td->o, cpumask)) {
		log_err("SPDK engine requires specifying CPUs (set cpus_allowed)\n");
		return -1;
	}

	if (opts->cpu_mask) {
		/* Already configured */
		return 0;
	}
	
	while (i < count) {
		if (fio_cpu_isset(&td->o.cpumask, cpu)) {
			spdk_cpuset_set_cpu(&cpuset, cpu, true);
			i++;
		} 
		cpu++;
	}
	if (0 == spdk_cpuset_count(&cpuset)) {
		log_err("SPDK cannot detect CPU cores to work on\n");
		return -1;
	}
	opts->cpu_mask = spdk_cpuset_fmt(&cpuset);

	return 0;
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

static int setup(struct thread_data *td)
{
	unsigned int i;
	struct fio_file *f;

	if (prepare_opts(td)) {
		return -1;
	}

	for_each_file(td, f, i) {
		f->real_file_size = 512 * 10000;
		f->filetype = FIO_TYPE_BLOCK;
		fio_file_set_size_known(f);
	}

	return 0;
}

static int init(struct thread_data *td)
{
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
