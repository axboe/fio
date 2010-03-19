#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include "debug.h"

#ifdef FIO_INC_DEBUG
void __dprint(int type, const char *str, ...)
{
	va_list args;
	pid_t pid;

	assert(type < FD_DEBUG_MAX);

	pid = getpid();
	if (fio_debug_jobp && *fio_debug_jobp != -1U
	    && pid != *fio_debug_jobp)
		return;

	log_info("%-8s ", debug_levels[type].name);
	log_info("%-5u ", (int) pid);

	va_start(args, str);
	log_valist(str, args);
	va_end(args);
}
#endif
