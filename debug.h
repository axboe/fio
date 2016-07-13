#ifndef FIO_DEBUG_H
#define FIO_DEBUG_H

#include <assert.h>
#include "log.h"

enum {
	FD_PROCESS	= 0,
	FD_FILE,
	FD_IO,
	FD_MEM,
	FD_BLKTRACE,
	FD_VERIFY,
	FD_RANDOM,
	FD_PARSE,
	FD_DISKUTIL,
	FD_JOB,
	FD_MUTEX,
	FD_PROFILE,
	FD_TIME,
	FD_NET,
	FD_RATE,
	FD_COMPRESS,
	FD_STEADYSTATE,
	FD_HELPERTHREAD,
	FD_DEBUG_MAX,
};

extern unsigned int fio_debug_jobno, *fio_debug_jobp;

#ifdef FIO_INC_DEBUG
struct debug_level {
	const char *name;
	const char *help;
	unsigned long shift;
	unsigned int jobno;
};
extern struct debug_level debug_levels[];

extern unsigned long fio_debug;

void __dprint(int type, const char *str, ...) __attribute__((format (printf, 2, 3)));

#define dprint(type, str, args...)			\
	do {						\
		if ((((1 << type)) & fio_debug) == 0)	\
			break;				\
		__dprint((type), (str), ##args);	\
	} while (0)					\

#else

static inline void dprint(int type, const char *str, ...)
{
}
#endif

#endif
