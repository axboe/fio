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
	FD_DEBUG_MAX,
};

#ifdef FIO_INC_DEBUG
struct debug_level {
	const char *name;
	unsigned long shift;
};
extern struct debug_level debug_levels[];

extern unsigned long fio_debug;

#define dprint(type, str, args...)				\
	do {							\
		assert(type < FD_DEBUG_MAX);			\
		if ((((1 << type)) & fio_debug) == 0)		\
			break;					\
		log_info("%-8s ", debug_levels[(type)].name);	\
		log_info(str, ##args);				\
	} while (0)

#else

#define dprint(type, str, args...)
#endif

#endif
