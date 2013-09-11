#ifndef FIO_LOG_H
#define FIO_LOG_H

#include <stdio.h>
#include <stdarg.h>

extern FILE *f_out;
extern FILE *f_err;

extern int log_err(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
extern int log_info(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));
extern int log_valist(const char *str, va_list);
extern int log_local_buf(const char *buf, size_t);
extern int log_info_flush(void);

enum {
	FIO_LOG_DEBUG	= 1,
	FIO_LOG_INFO	= 2,
	FIO_LOG_ERR	= 3,
	FIO_LOG_NR	= 4,
};

extern const char *log_get_level(int level);

#endif
