#ifndef FIO_GETTIME_H
#define FIO_GETTIME_H

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
extern int fio_monotonic_clocktest(void);
extern void fio_local_clock_init(int);

extern struct timeval *fio_tv;

#endif
