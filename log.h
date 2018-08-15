#ifndef FIO_LOG_H
#define FIO_LOG_H

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>

#include "lib/output_buffer.h"

extern FILE *f_out;
extern FILE *f_err;

extern ssize_t log_err(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
extern ssize_t log_info(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
extern size_t __log_buf(struct buf_output *, const char *format, ...) __attribute__ ((__format__ (__printf__, 2, 3)));
extern size_t log_valist(const char *str, va_list);
extern void log_prevalist(int type, const char *str, va_list);
extern size_t log_info_buf(const char *buf, size_t len);
extern int log_info_flush(void);

#define log_buf(buf, format, args...)			\
({							\
	size_t __ret;					\
	if ((buf) != NULL)				\
		__ret = __log_buf(buf, format, ##args);	\
	else						\
		__ret = log_info(format, ##args);	\
	__ret;						\
})

enum {
	FIO_LOG_DEBUG	= 1,
	FIO_LOG_INFO	= 2,
	FIO_LOG_ERR	= 3,
	FIO_LOG_NR	= 4,
};

extern const char *log_get_level(int level);

#endif
