#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "oslib/asprintf.h"

#ifndef CONFIG_HAVE_VASPRINTF
int vasprintf(char **strp, const char *fmt, va_list ap)
{
	va_list ap_copy;
	char *str;
	int len;

#ifdef va_copy
	va_copy(ap_copy, ap);
#else
	__va_copy(ap_copy, ap);
#endif
	len = vsnprintf(NULL, 0, fmt, ap_copy);
	va_end(ap_copy);

	if (len < 0)
		return len;

	len++;
	str = malloc(len);
	*strp = str;
	return str ? vsnprintf(str, len, fmt, ap) : -1;
}
#endif

#ifndef CONFIG_HAVE_ASPRINTF
int asprintf(char **strp, const char *fmt, ...)
{
	va_list arg;
	int done;

	va_start(arg, fmt);
	done = vasprintf(strp, fmt, arg);
	va_end(arg);

	return done;
}
#endif
