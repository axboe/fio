#ifndef FIO_TIME_H
#define FIO_TIME_H

#include <stdint.h>
/* IWYU pragma: begin_exports */
#include <time.h>
#include <sys/time.h>
/* IWYU pragma: end_exports */
#include "lib/types.h"

#define RAMP_PERIOD_CHECK_MSEC 1000

extern bool ramp_period_enabled;

struct thread_data;
extern uint64_t ntime_since(const struct timespec *, const struct timespec *);
extern uint64_t ntime_since_now(const struct timespec *);
extern uint64_t utime_since(const struct timespec *, const struct timespec *);
extern uint64_t utime_since_now(const struct timespec *);
extern int64_t rel_time_since(const struct timespec *,
			      const struct timespec *);
extern uint64_t mtime_since(const struct timespec *, const struct timespec *);
extern uint64_t mtime_since_now(const struct timespec *);
extern uint64_t mtime_since_tv(const struct timeval *, const struct timeval *);
extern uint64_t time_since_now(const struct timespec *);
extern uint64_t time_since_genesis(void);
extern uint64_t mtime_since_genesis(void);
extern uint64_t utime_since_genesis(void);
extern void cycles_spin(unsigned int);
extern uint64_t usec_spin(unsigned int);
extern uint64_t usec_sleep(struct thread_data *, unsigned long);
extern void fill_start_time(struct timespec *);
extern void set_genesis_time(void);
extern int ramp_period_check(void);
extern bool ramp_period_over(struct thread_data *);
extern bool in_ramp_period(struct thread_data *);
extern int td_ramp_period_init(struct thread_data *);
extern void fio_time_init(void);
extern void timespec_add_msec(struct timespec *, unsigned int);
extern void set_epoch_time(struct thread_data *, clockid_t, clockid_t);

#endif
