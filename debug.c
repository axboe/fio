#include <assert.h>
#include <stdarg.h>

#include "debug.h"
#include "log.h"

#ifdef FIO_INC_DEBUG
void __dprint(int type, const char *str, ...)
{
	va_list args;

	assert(type < FD_DEBUG_MAX);

	va_start(args, str);
	log_prevalist(type, str, args);
	va_end(args);
}
#endif
