#ifndef _NOWARN_SNPRINTF_H_
#define _NOWARN_SNPRINTF_H_

#include <stdio.h>
#include <stdarg.h>

static inline int nowarn_snprintf(char *str, size_t size, const char *format,
				  ...)
{
	va_list args;
	int res;

	va_start(args, format);
#if __GNUC__ -0 >= 8
#pragma GCC diagnostic push "-Wformat-truncation"
#pragma GCC diagnostic ignored "-Wformat-truncation"
#endif
	res = vsnprintf(str, size, format, args);
#if __GNUC__ -0 >= 8
#pragma GCC diagnostic pop "-Wformat-truncation"
#endif
	va_end(args);

	return res;
}

#endif
