#ifndef FIO_STEADYSTATE_H
#define FIO_STEADYSTATE_H

extern void steadystate_check(void);
extern void steadystate_setup(void);
extern void steadystate_alloc(struct thread_data *);
extern bool steadystate_deviation(unsigned long, unsigned long, struct thread_data *);
extern bool steadystate_slope(unsigned long, unsigned long, struct thread_data *);

/*
 * For steady state detection
 */
struct steadystate_data {
	double limit;
	unsigned long long dur;
	unsigned long long ramp_time;
	bool (*evaluate)(unsigned long, unsigned long, struct thread_data *);
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

#endif
