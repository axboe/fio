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
	FD_DEBUG_MAX,
};

#ifdef FIO_INC_DEBUG
struct debug_level {
	const char *name;
	unsigned long shift;
	unsigned int jobno;
};
extern struct debug_level debug_levels[];

extern unsigned long fio_debug;
extern unsigned int fio_debug_jobno, *fio_debug_jobp;

#define dprint(type, str, args...)				\
	do {							\
		pid_t pid = getpid();				\
		assert(type < FD_DEBUG_MAX);			\
		if ((((1 << type)) & fio_debug) == 0)		\
			break;					\
		if (fio_debug_jobp && *fio_debug_jobp != -1U	\
		    && pid != *fio_debug_jobp)			\
			break;					\
		log_info("%-8s ", debug_levels[(type)].name);	\
		log_info("%-5u ", (int) pid);			\
		log_info(str, ##args);				\
	} while (0)

#else

#define dprint(type, str, args...)
#endif

#endif
