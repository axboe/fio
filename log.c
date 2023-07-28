#include "log.h"

#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>

#include "fio.h"
#include "oslib/asprintf.h"

size_t log_info_buf(const char *buf, size_t len)
{
	/*
	 * buf could be NULL (not just "").
	 */
	if (!buf)
		return 0;

	if (is_backend) {
		ssize_t ret = fio_server_text_output(FIO_LOG_INFO, buf, len);
		if (ret != -1)
			return ret;
	}

	if (log_syslog) {
		syslog(LOG_INFO, "%s", buf);
		return len;
	} else
		return fwrite(buf, len, 1, f_out);
}

size_t log_valist(const char *fmt, va_list args)
{
	char *buffer;
	int len;

	len = vasprintf(&buffer, fmt, args);
	if (len < 0)
		return 0;
	len = log_info_buf(buffer, len);
	free(buffer);

	return len;
}

/* add prefix for the specified type in front of the valist */
#ifdef FIO_INC_DEBUG
void log_prevalist(int type, const char *fmt, va_list args)
{
	char *buf1, *buf2;
	int len;
	pid_t pid;

	pid = gettid();
	if (fio_debug_jobp && *fio_debug_jobp != -1U
	    && pid != *fio_debug_jobp)
		return;

	len = vasprintf(&buf1, fmt, args);
	if (len < 0)
		return;
	len = asprintf(&buf2, "%-8s %-5u %s", debug_levels[type].name,
		       (int) pid, buf1);
	free(buf1);
	if (len < 0)
		return;
	log_info_buf(buf2, len);
	free(buf2);
}
#endif

ssize_t log_info(const char *format, ...)
{
	va_list args;
	ssize_t ret;

	va_start(args, format);
	ret = log_valist(format, args);
	va_end(args);

	return ret;
}

size_t __log_buf(struct buf_output *buf, const char *format, ...)
{
	char *buffer;
	va_list args;
	int len;

	va_start(args, format);
	len = vasprintf(&buffer, format, args);
	va_end(args);
	if (len < 0)
		return 0;
	len = buf_output_add(buf, buffer, len);
	free(buffer);

	return len;
}

int log_info_flush(void)
{
	if (is_backend || log_syslog)
		return 0;

	return fflush(f_out);
}

ssize_t log_err(const char *format, ...)
{
	ssize_t ret;
	int len;
	char *buffer;
	va_list args;

	va_start(args, format);
	len = vasprintf(&buffer, format, args);
	va_end(args);
	if (len < 0)
		return len;

	if (is_backend) {
		ret = fio_server_text_output(FIO_LOG_ERR, buffer, len);
		if (ret != -1)
			goto done;
	}

	if (log_syslog) {
		syslog(LOG_INFO, "%s", buffer);
		ret = len;
	} else {
		if (f_err != stderr)
			ret = fwrite(buffer, len, 1, stderr);

		ret = fwrite(buffer, len, 1, f_err);
	}

done:
	free(buffer);
	return ret;
}

const char *log_get_level(int level)
{
	static const char *levels[] = { "Unknown", "Debug", "Info", "Error",
						"Unknown" };

	if (level >= FIO_LOG_NR)
		level = FIO_LOG_NR;

	return levels[level];
}
