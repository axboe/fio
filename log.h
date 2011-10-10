#ifndef FIO_LOG_H
#define FIO_LOG_H

#include <stdio.h>
#include <stdarg.h>

extern FILE *f_out;
extern FILE *f_err;

extern int log_err(const char *format, ...);
extern int log_info(const char *format, ...);
extern int log_local(const char *format, ...);
extern int log_valist(const char *str, va_list);
extern int log_local_buf(const char *buf, size_t);

#endif
