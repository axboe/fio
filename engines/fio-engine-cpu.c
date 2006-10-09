#include "fio.h"
#include "os.h"

static int fio_cpuio_init(struct thread_data *td)
{
	if (!td->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate");
		return 1;
	} else if (td->cpuload > 100)
		td->cpuload = 100;

	td->read_iolog = td->write_iolog = 0;
	td->fd = -1;

	return 0;
}

struct ioengine_ops ioengine = {
	.name		= "cpuio",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_cpuio_init,
	.flags		= FIO_CPUIO,
};
