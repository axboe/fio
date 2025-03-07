#ifndef FIO_GETTIME_H
#define FIO_GETTIME_H

#include <sys/time.h>

#include "arch/arch.h"
#include "lib/seqlock.h"

/*
 * Clock sources
 */
enum fio_cs {
	CS_GTOD		= 1,
	CS_CGETTIME,
	CS_CPUCLOCK,
	CS_INVAL,
};

extern int fio_get_mono_time(struct timespec *);
extern void fio_gettime(struct timespec *, void *);
extern void fio_gtod_init(void);
extern void fio_clock_init(void);
extern int fio_start_gtod_thread(void);
extern int fio_monotonic_clocktest(int debug);
extern void fio_local_clock_init(void);

extern struct fio_ts {
	struct seqlock seqlock;
	struct timespec ts;
} *fio_ts;

static inline int fio_gettime_offload(struct timespec *ts)
{
	unsigned int seq;

	if (!fio_ts)
		return 0;

	do {
		seq = read_seqlock_begin(&fio_ts->seqlock);
		*ts = fio_ts->ts;
	} while (read_seqlock_retry(&fio_ts->seqlock, seq));

	return 1;
}

extern void fio_gtod_set_cpu(unsigned int cpu);

#endif
