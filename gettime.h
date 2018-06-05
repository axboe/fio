#ifndef FIO_GETTIME_H
#define FIO_GETTIME_H

#include <sys/time.h>

#include "arch/arch.h"

/*
 * Clock sources
 */
enum fio_cs {
	CS_GTOD		= 1,
	CS_CGETTIME,
	CS_CPUCLOCK,
	CS_INVAL,
};

extern void fio_gettime(struct timespec *, void *);
extern void fio_gtod_init(void);
extern void fio_clock_init(void);
extern int fio_start_gtod_thread(void);
extern int fio_monotonic_clocktest(int debug);
extern void fio_local_clock_init(void);

extern struct timespec *fio_ts;

static inline int fio_gettime_offload(struct timespec *ts)
{
	time_t last_sec;

	if (!fio_ts)
		return 0;

	do {
		read_barrier();
		last_sec = ts->tv_sec = fio_ts->tv_sec;
		ts->tv_nsec = fio_ts->tv_nsec;
	} while (fio_ts->tv_sec != last_sec);

	return 1;
}

extern void fio_gtod_set_cpu(unsigned int cpu);

#endif
