#include "log.h"

#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>

#include "fio.h"
#include "oslib/asprintf.h"

/*
 * When a JSON output format was requested, the JSON document is the
 * only thing that may ever appear on the stream carrying it
 * (f_out, i.e. the --output file or stdout).  Everything else has to
 * go elsewhere, even if no separate output file was given.  With json
 * output in effect, informational and error output is therefore sent
 * to stderr instead of f_out.  Without json output, messages keep
 * going to f_out as they always have.
 */
bool fio_output_json(void)
{
	return (output_format & FIO_OUTPUT_JSON) != 0;
}

/*
 * Stream for other requested output formats while json output owns
 * the primary stream: stdout, unless fio writes the json output there
 * itself, in which case it is stderr.
 */
FILE *fio_output_secondary(void)
{
	if (f_out == stdout)
		return stderr;
	return stdout;
}

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
	} else if (fio_output_json())
		return fwrite(buf, len, 1, stderr);
	else
		return fwrite(buf, len, 1, f_out);
}

/*
 * The json formatted results.  Always written to the primary output
 * stream, where the document stays the only content.
 */
size_t log_json_buf(const char *buf, size_t len)
{
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

/*
 * Human readable or other non-json formatted results.  When json
 * output is active these go to the secondary stream so they cannot
 * break the json document.
 */
size_t log_human_buf(const char *buf, size_t len)
{
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
	} else if (fio_output_json())
		return fwrite(buf, len, 1, fio_output_secondary());
	else
		return fwrite(buf, len, 1, f_out);
}

ssize_t log_human(const char *format, ...)
{
	char *buffer;
	va_list args;
	int len;

	va_start(args, format);
	len = vasprintf(&buffer, format, args);
	va_end(args);
	if (len < 0)
		return 0;
	len = log_human_buf(buffer, len);
	free(buffer);

	return len;
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

	/* keep periodic json output (status-interval) flushing */
	fflush(stderr);
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
	} else if (fio_output_json()) {
		ret = fwrite(buffer, len, 1, stderr);
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
