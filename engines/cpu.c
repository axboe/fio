/*
 * CPU engine
 *
 * Doesn't transfer any data, merely burns CPU cycles according to
 * the settings.
 *
 */
#include "../fio.h"

static int fio_cpuio_queue(struct thread_data *td, struct io_u fio_unused *io_u)
{
	usec_spin(td->o.cpucycle);
	return FIO_Q_COMPLETED;
}

static int fio_cpuio_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	if (!o->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate (cpuload=)","cpuio");
		return 1;
	}

	if (o->cpuload > 100)
		o->cpuload = 100;

	/*
	 * set thinktime_sleep and thinktime_spin appropriately
	 */
	o->thinktime_blocks = 1;
	o->thinktime_spin = 0;
	o->thinktime = (o->cpucycle * (100 - o->cpuload)) / o->cpuload;

	o->nr_files = o->open_files = 1;
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
};

static void fio_init fio_cpuio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cpuio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
