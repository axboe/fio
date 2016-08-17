#ifndef FIO_STEADYSTATE_H
#define FIO_STEADYSTATE_H

#include "thread_options.h"

extern void steadystate_check(void);
extern void steadystate_setup(void);
extern void td_steadystate_init(struct thread_data *);

extern bool steadystate_enabled;

/*
 * For steady state detection
 */
struct steadystate_data {
	double limit;
	unsigned long long dur;
	unsigned long long ramp_time;
	bool pct;

	unsigned int mode;
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
	__FIO_SS_IOPS		= 1,
	__FIO_SS_BW		= 2,
	__FIO_SS_SLOPE		= 4,
	__FIO_SS_ATTAINED	= 8,

	FIO_SS_IOPS		= __FIO_SS_IOPS,
	FIO_SS_IOPS_SLOPE	= __FIO_SS_IOPS | __FIO_SS_SLOPE,
	FIO_SS_BW		= __FIO_SS_BW,
	FIO_SS_BW_SLOPE		= __FIO_SS_BW | __FIO_SS_SLOPE,
};

#define STEADYSTATE_MSEC	1000

#endif
