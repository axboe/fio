#ifndef FIO_STEADYSTATE_H
#define FIO_STEADYSTATE_H

#include "thread_options.h"

extern void steadystate_check(void);
extern void steadystate_setup(void);
extern void steadystate_alloc(struct thread_data *);

extern bool steadystate_enabled;

/*
 * For steady state detection
 */
struct steadystate_data {
	double limit;
	unsigned long long dur;
	unsigned long long ramp_time;
	bool check_iops;
	bool check_slope;
	bool pct;

	int attained;
	int last_in_group;
	int ramp_time_over;

	unsigned int head;
	unsigned int tail;
	unsigned long *iops_data;
	unsigned long *bw_data;

	double slope;
	double criterion;
	double deviation;

	unsigned long long sum_y;
	unsigned long long sum_x;
	unsigned long long sum_x_sq;
	unsigned long long sum_xy;
	unsigned long long oldest_y;

	struct timeval prev_time;
	unsigned long long prev_iops;
	unsigned long long prev_bytes;
};

enum {
	FIO_STEADYSTATE_IOPS	= 0,
	FIO_STEADYSTATE_IOPS_SLOPE,
	FIO_STEADYSTATE_BW,
	FIO_STEADYSTATE_BW_SLOPE,
};

#define STEADYSTATE_MSEC	1000

static inline bool steadystate_check_slope(struct thread_options *o)
{
	return o->ss == FIO_STEADYSTATE_IOPS_SLOPE ||
		o->ss == FIO_STEADYSTATE_BW_SLOPE;
}

static inline bool steadystate_check_iops(struct thread_options *o)
{
	return o->ss == FIO_STEADYSTATE_IOPS ||
		o->ss == FIO_STEADYSTATE_IOPS_SLOPE;
}

#endif
