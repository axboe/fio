#include <errno.h>
#include "getrusage.h"

int fio_getrusage(struct rusage *ru)
{
#ifdef CONFIG_RUSAGE_THREAD
	if (!getrusage(RUSAGE_THREAD, ru))
		return 0;
	if (errno != EINVAL)
		return -1;
	/* Fall through to RUSAGE_SELF */
#endif
	return getrusage(RUSAGE_SELF, ru);
}
