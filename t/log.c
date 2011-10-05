#include <stdio.h>
#include <stdarg.h>

int log_err(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	return fwrite(buffer, len, 1, stderr);
}
