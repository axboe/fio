#include <stdio.h>

FILE *f_err;
struct timespec *fio_ts = NULL;
unsigned long fio_debug = 0;

void __dprint(int type, const char *str, ...)
{
}

void debug_init(void)
{
	f_err = stderr;
}
