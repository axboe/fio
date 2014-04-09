/*
 * CPU engine
 *
 * Doesn't transfer any data, merely burns CPU cycles according to
 * the settings.
 *
 */
#include "../fio.h"

struct cpu_options {
	struct thread_data *td;
	unsigned int cpuload;
	unsigned int cpucycle;
	unsigned int exit_io_done;
};

static struct fio_option options[] = {
	{
		.name	= "cpuload",
		.lname	= "CPU load",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct cpu_options, cpuload),
		.help	= "Use this percentage of CPU",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "cpuchunks",
		.lname	= "CPU chunk",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct cpu_options, cpucycle),
		.help	= "Length of the CPU burn cycles (usecs)",
		.def	= "50000",
		.parent = "cpuload",
		.hide	= 1,
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "exit_on_io_done",
		.lname	= "Exit when IO threads are done",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct cpu_options, exit_io_done),
		.help	= "Exit when IO threads finish",
		.def	= "0",
		.category = FIO_OPT_C_GENERAL,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= NULL,
	},
};


static int fio_cpuio_queue(struct thread_data *td, struct io_u fio_unused *io_u)
{
	struct cpu_options *co = td->eo;

	if (co->exit_io_done && !fio_running_or_pending_io_threads()) {
		td->done = 1;
		return FIO_Q_BUSY;
	}

	usec_spin(co->cpucycle);
	return FIO_Q_COMPLETED;
}

static int fio_cpuio_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	struct cpu_options *co = td->eo;

	if (!co->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate (cpuload=)","cpuio");
		return 1;
	}

	if (co->cpuload > 100)
		co->cpuload = 100;

	/*
	 * set thinktime_sleep and thinktime_spin appropriately
	 */
	o->thinktime_blocks = 1;
	o->thinktime_spin = 0;
	o->thinktime = (co->cpucycle * (100 - co->cpuload)) / co->cpuload;

	o->nr_files = o->open_files = 1;

	log_info("%s: ioengine=cpu, cpuload=%u, cpucycle=%u\n", td->o.name,
						co->cpuload, co->cpucycle);

	return 0;
}

static int fio_cpuio_open(struct thread_data fio_unused *td,
			  struct fio_file fio_unused *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "cpuio",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_cpuio_queue,
	.init		= fio_cpuio_init,
	.open_file	= fio_cpuio_open,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO | FIO_NOIO,
	.options		= options,
	.option_struct_size	= sizeof(struct cpu_options),
};

static void fio_init fio_cpuio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cpuio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
