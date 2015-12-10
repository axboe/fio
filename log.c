#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>

#include "fio.h"

size_t log_info_buf(const char *buf, size_t len)
{
	if (is_backend) {
		size_t ret = fio_server_text_output(FIO_LOG_INFO, buf, len);
		if (ret != -1)
			return ret;
	}

	if (log_syslog) {
		syslog(LOG_INFO, "%s", buf);
		return len;
	} else
		return fwrite(buf, len, 1, f_out);
}

size_t log_valist(const char *str, va_list args)
{
	char buffer[1024];
	size_t len;

	len = vsnprintf(buffer, sizeof(buffer), str, args);

	return log_info_buf(buffer, min(len, sizeof(buffer) - 1));
}

size_t log_info(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	return log_info_buf(buffer, min(len, sizeof(buffer) - 1));
}

size_t __log_buf(struct buf_output *buf, const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	return buf_output_add(buf, buffer, min(len, sizeof(buffer) - 1));
}

int log_info_flush(void)
{
	if (is_backend || log_syslog)
		return 0;

	return fflush(f_out);
}

size_t log_err(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);
	len = min(len, sizeof(buffer) - 1);

	if (is_backend) {
		size_t ret = fio_server_text_output(FIO_LOG_ERR, buffer, len);
		if (ret != -1)
			return ret;
	}

	if (log_syslog) {
		syslog(LOG_INFO, "%s", buffer);
		return len;
	} else {
		if (f_err != stderr) {
			int fio_unused ret;

			ret = fwrite(buffer, len, 1, stderr);
		}

		return fwrite(buffer, len, 1, f_err);
	}
}

const char *log_get_level(int level)
{
	static const char *levels[] = { "Unknown", "Debug", "Info", "Error",
						"Unknown" };

	if (level >= FIO_LOG_NR)
		level = FIO_LOG_NR;

	return levels[level];
}
