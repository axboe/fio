#ifndef FIO_TIME_H
#define FIO_TIME_H

#include "lib/types.h"

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
extern bool ramp_time_over(struct thread_data *);
extern bool in_ramp_time(struct thread_data *);
extern void fio_time_init(void);
extern void timeval_add_msec(struct timeval *, unsigned int);
extern void set_epoch_time(struct thread_data *, int);

#endif
