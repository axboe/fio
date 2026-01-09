#ifndef FIO_STEADYSTATE_H
#define FIO_STEADYSTATE_H

#include "thread_options.h"

extern void steadystate_free(struct thread_data *);
extern int steadystate_check(void);
extern void steadystate_setup(void);
extern int td_steadystate_init(struct thread_data *);
extern uint64_t steadystate_bw_mean(const struct thread_stat *);
extern uint64_t steadystate_iops_mean(const struct thread_stat *);
extern uint64_t steadystate_lat_mean(const struct thread_stat *);

extern bool steadystate_enabled;
extern unsigned int ss_check_interval;

struct steadystate_data {
	double limit;
	unsigned long long dur;
	unsigned long long ramp_time;

	uint32_t state;

	unsigned int head;
	unsigned int tail;
	uint64_t *iops_data;
	uint64_t *bw_data;
	uint64_t *lat_data;

	double slope;
	double deviation;
	double criterion;

	uint64_t sum_y;
	uint64_t sum_x;
	uint64_t sum_x_sq;
	uint64_t sum_xy;
	uint64_t oldest_y;

	struct timespec prev_time;
	uint64_t prev_iops;
	uint64_t prev_bytes;
	double prev_lat_sum;
	uint64_t prev_lat_samples;
};

enum {
	__FIO_SS_IOPS = 0,
	__FIO_SS_BW,
	__FIO_SS_SLOPE,
	__FIO_SS_ATTAINED,
	__FIO_SS_RAMP_OVER,
	__FIO_SS_DATA,
	__FIO_SS_PCT,
	__FIO_SS_BUFFER_FULL,
	__FIO_SS_LAT,
};

enum {
	FIO_SS_IOPS		= 1 << __FIO_SS_IOPS,
	FIO_SS_BW		= 1 << __FIO_SS_BW,
	FIO_SS_SLOPE		= 1 << __FIO_SS_SLOPE,
	FIO_SS_ATTAINED		= 1 << __FIO_SS_ATTAINED,
	FIO_SS_RAMP_OVER	= 1 << __FIO_SS_RAMP_OVER,
	FIO_SS_DATA		= 1 << __FIO_SS_DATA,
	FIO_SS_PCT		= 1 << __FIO_SS_PCT,
	FIO_SS_BUFFER_FULL	= 1 << __FIO_SS_BUFFER_FULL,
	FIO_SS_LAT		= 1 << __FIO_SS_LAT,

	FIO_SS_IOPS_SLOPE	= FIO_SS_IOPS | FIO_SS_SLOPE,
	FIO_SS_BW_SLOPE		= FIO_SS_BW | FIO_SS_SLOPE,
	FIO_SS_LAT_SLOPE	= FIO_SS_LAT | FIO_SS_SLOPE,
};

#endif
