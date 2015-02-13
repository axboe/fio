#ifndef FIO_GETTIME_H
#define FIO_GETTIME_H

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

extern void fio_gettime(struct timeval *, void *);
extern void fio_gtod_init(void);
extern void fio_clock_init(void);
extern int fio_start_gtod_thread(void);
extern int fio_monotonic_clocktest(int debug);
extern void fio_local_clock_init(int);

extern struct timeval *fio_tv;

static inline int fio_gettime_offload(struct timeval *tv)
{
	time_t last_sec;

	if (!fio_tv)
		return 0;

	do {
		read_barrier();
		last_sec = tv->tv_sec = fio_tv->tv_sec;
		tv->tv_usec = fio_tv->tv_usec;
	} while (fio_tv->tv_sec != last_sec);

	return 1;
}

extern void fio_gtod_set_cpu(unsigned int cpu);

#endif
