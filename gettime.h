#ifndef FIO_GETTIME_H
#define FIO_GETTIME_H

/*
 * Clock sources
 */
enum fio_cs {
	CS_GTOD		= 1,
	CS_CGETTIME,
	CS_CPUCLOCK,
};

extern void fio_gettime(struct timeval *, void *);
extern void fio_gtod_init(void);
extern void fio_clock_init(void);
extern int fio_start_gtod_thread(void);

#endif
