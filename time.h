#ifndef FIO_TIME_H
#define FIO_TIME_H

extern unsigned long long utime_since(struct timeval *, struct timeval *);
extern unsigned long long utime_since_now(struct timeval *);
extern unsigned long mtime_since(struct timeval *, struct timeval *);
extern unsigned long mtime_since_now(struct timeval *);
extern unsigned long time_since_now(struct timeval *);
extern unsigned long mtime_since_genesis(void);
extern void usec_spin(unsigned int);
extern void usec_sleep(struct thread_data *, unsigned long);
extern void fill_start_time(struct timeval *);
extern void set_genesis_time(void);
extern int ramp_time_over(struct thread_data *);
extern int in_ramp_time(struct thread_data *);
extern unsigned long long genesis_cycles;
extern void fio_time_init(void);

#endif
