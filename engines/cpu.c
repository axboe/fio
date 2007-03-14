/*
 * CPU engine
 *
 * Doesn't transfer any data, merely burns CPU cycles according to
 * the settings.
 *
 */
#include "../fio.h"
#include "../os.h"

static int fio_cpuio_queue(struct thread_data *td, struct io_u fio_unused *io_u)
{
	__usec_sleep(td->cpucycle);
	return FIO_Q_COMPLETED;
}

static int fio_cpuio_setup(struct thread_data fio_unused *td)
{
	struct fio_file *f;
	unsigned int i;

	td->total_file_size = -1;
	td->io_size = td->total_file_size;
	td->total_io_size = td->io_size;

	for_each_file(td, f, i) {
		f->real_file_size = -1;
		f->file_size = -1;
	}

	return 0;
}

static int fio_cpuio_init(struct thread_data *td)
{
	if (!td->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate (cpuload=)","cpuio");
		return 1;
	}

	if (td->cpuload > 100)
		td->cpuload = 100;

	/*
	 * set thinktime_sleep and thinktime_spin appropriately
	 */
	td->thinktime_blocks = 1;
	td->thinktime_spin = 0;
	td->thinktime = (td->cpucycle * (100 - td->cpuload)) / td->cpuload;

	td->nr_files = td->open_files = 1;
	return 0;
}

static int fio_cpuio_open(struct thread_data fio_unused *td, struct fio_file *f)
{
	f->fd = 0;
	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "cpuio",
	.version	= FIO_IOOPS_VERSION,
	.queue		= fio_cpuio_queue,
	.init		= fio_cpuio_init,
	.setup		= fio_cpuio_setup,
	.open_file	= fio_cpuio_open,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_cpuio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cpuio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
