#ifndef FIO_TIME_H
#define FIO_TIME_H

extern uint64_t utime_since(struct timeval *, struct timeval *);
extern uint64_t utime_since_now(struct timeval *);
extern uint64_t mtime_since(struct timeval *, struct timeval *);
extern uint64_t mtime_since_now(struct timeval *);
extern uint64_t time_since_now(struct timeval *);
extern uint64_t mtime_since_genesis(void);
extern void usec_spin(unsigned int);
extern void usec_sleep(struct thread_data *, unsigned long);
extern void fill_start_time(struct timeval *);
extern void set_genesis_time(void);
extern int ramp_time_over(struct thread_data *);
extern int in_ramp_time(struct thread_data *);
extern void fio_time_init(void);

#endif
