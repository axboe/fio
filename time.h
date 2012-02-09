#ifndef FIO_TIME_H
#define FIO_TIME_H

/*
 * Clock sources
 */
enum fio_cs {
	CS_GTOD		= 1,
	CS_CGETTIME,
	CS_CPUCLOCK,
};

extern unsigned long long utime_since(struct timeval *, struct timeval *);
extern unsigned long long utime_since_now(struct timeval *);
extern unsigned long mtime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since_now(struct timeval *);
extern unsigned long time_since_now(struct timeval *);
extern unsigned long mtime_since_genesis(void);
extern void usec_spin(unsigned int);
extern void usec_sleep(struct thread_data *, unsigned long);
extern void fill_start_time(struct timeval *);
extern void fio_gettime(struct timeval *, void *);
extern void fio_gtod_init(void);
extern void fio_clock_init(void);
extern void fio_gtod_update(void);
extern void set_genesis_time(void);
extern int ramp_time_over(struct thread_data *);
extern int in_ramp_time(struct thread_data *);
extern unsigned long long genesis_cycles;
extern void fio_time_init(void);
extern int fio_start_gtod_thread(void);

#endif
