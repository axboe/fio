#ifndef FIO_LOG_H
#define FIO_LOG_H

#include <stdio.h>

extern FILE *f_out;
extern FILE *f_err;

/*
 * If logging output to a file, stderr should go to both stderr and f_err
 */
#define log_err(args, ...)	do {				\
	fprintf(f_err, args,  ##__VA_ARGS__);		\
	if (f_err != stderr)						\
		fprintf(stderr, args,  ##__VA_ARGS__);	\
	} while (0)

#define log_info(args, ...)	fprintf(f_out, args, ##__VA_ARGS__)
#define log_valist(str, args)	vfprintf(f_out, (str), (args))

FILE *get_f_out(void);
FILE *get_f_err(void);

#endif
