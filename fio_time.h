#ifndef FIO_TIME_H
#define FIO_TIME_H

struct thread_data;
extern uint64_t utime_since(const struct timeval *,const  struct timeval *);
extern uint64_t utime_since_now(const struct timeval *);
extern uint64_t mtime_since(const struct timeval *, const struct timeval *);
extern uint64_t mtime_since_now(const struct timeval *);
extern uint64_t time_since_now(const struct timeval *);
extern uint64_t time_since_genesis(void);
extern uint64_t mtime_since_genesis(void);
extern uint64_t utime_since_genesis(void);
extern uint64_t usec_spin(unsigned int);
extern uint64_t usec_sleep(struct thread_data *, unsigned long);
extern void fill_start_time(struct timeval *);
extern void set_genesis_time(void);
extern int ramp_time_over(struct thread_data *);
extern int in_ramp_time(struct thread_data *);
extern void fio_time_init(void);

#endif
