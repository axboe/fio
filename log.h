#ifndef FIO_LOG_H
#define FIO_LOG_H

#include <stdio.h>

extern FILE *f_out;
extern FILE *f_err;

extern int log_err(const char *format, ...);
extern int log_info(const char *format, ...);

#define log_valist(str, args)	vfprintf(f_out, (str), (args))

#endif
