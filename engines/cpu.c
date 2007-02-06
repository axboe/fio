#include "../fio.h"
#include "../os.h"

static int fio_cpuio_setup(struct thread_data fio_unused *td)
{
	return 0;
}

static int fio_cpuio_init(struct thread_data *td)
{
	if (!td->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate");
		return 1;
	} else if (td->cpuload > 100)
		td->cpuload = 100;

	td->nr_files = 0;

	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "cpuio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_cpuio_init,
	.setup		= fio_cpuio_setup,
	.flags		= FIO_CPUIO,
};

static void fio_init fio_cpuio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cpuio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
