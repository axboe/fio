#ifndef FIO_STAT_H
#define FIO_STAT_H

#include "iolog.h"

struct group_run_stats {
	uint64_t max_run[DDIR_RWDIR_CNT], min_run[DDIR_RWDIR_CNT];
	uint64_t max_bw[DDIR_RWDIR_CNT], min_bw[DDIR_RWDIR_CNT];
	uint64_t io_kb[DDIR_RWDIR_CNT];
	uint64_t agg[DDIR_RWDIR_CNT];
	uint32_t kb_base;
	uint32_t unit_base;
	uint32_t groupid;
	uint32_t unified_rw_rep;
};

/*
 * How many depth levels to log
 */
#define FIO_IO_U_MAP_NR	7
#define FIO_IO_U_LAT_U_NR 10
#define FIO_IO_U_LAT_M_NR 12

/*
 * Aggregate clat samples to report percentile(s) of them.
 *
 * EXECUTIVE SUMMARY
 *
 * FIO_IO_U_PLAT_BITS determines the maximum statistical error on the
 * value of resulting percentiles. The error will be approximately
 * 1/2^(FIO_IO_U_PLAT_BITS+1) of the value.
 *
 * FIO_IO_U_PLAT_GROUP_NR and FIO_IO_U_PLAT_BITS determine the maximum
 * range being tracked for latency samples. The maximum value tracked
 * accurately will be 2^(GROUP_NR + PLAT_BITS -1) microseconds.
 *
 * FIO_IO_U_PLAT_GROUP_NR and FIO_IO_U_PLAT_BITS determine the memory
 * requirement of storing those aggregate counts. The memory used will
 * be (FIO_IO_U_PLAT_GROUP_NR * 2^FIO_IO_U_PLAT_BITS) * sizeof(int)
 * bytes.
 *
 * FIO_IO_U_PLAT_NR is the total number of buckets.
 *
 * DETAILS
 *
 * Suppose the clat varies from 0 to 999 (usec), the straightforward
 * method is to keep an array of (999 + 1) buckets, in which a counter
 * keeps the count of samples which fall in the bucket, e.g.,
 * {[0],[1],...,[999]}. However this consumes a huge amount of space,
 * and can be avoided if an approximation is acceptable.
 *
 * One such method is to let the range of the bucket to be greater
 * than one. This method has low accuracy when the value is small. For
 * example, let the buckets be {[0,99],[100,199],...,[900,999]}, and
 * the represented value of each bucket be the mean of the range. Then
 * a value 0 has an round-off error of 49.5. To improve on this, we
 * use buckets with non-uniform ranges, while bounding the error of
 * each bucket within a ratio of the sample value. A simple example
 * would be when error_bound = 0.005, buckets are {
 * {[0],[1],...,[99]}, {[100,101],[102,103],...,[198,199]},..,
 * {[900,909],[910,919]...}  }. The total range is partitioned into
 * groups with different ranges, then buckets with uniform ranges. An
 * upper bound of the error is (range_of_bucket/2)/value_of_bucket
 *
 * For better efficiency, we implement this using base two. We group
 * samples by their Most Significant Bit (MSB), extract the next M bit
 * of them as an index within the group, and discard the rest of the
 * bits.
 *
 * E.g., assume a sample 'x' whose MSB is bit n (starting from bit 0),
 * and use M bit for indexing
 *
 *        | n |    M bits   | bit (n-M-1) ... bit 0 |
 *
 * Because x is at least 2^n, and bit 0 to bit (n-M-1) is at most
 * (2^(n-M) - 1), discarding bit 0 to (n-M-1) makes the round-off
 * error
 *
 *           2^(n-M)-1    2^(n-M)    1
 *      e <= --------- <= ------- = ---
 *             2^n          2^n     2^M
 *
 * Furthermore, we use "mean" of the range to represent the bucket,
 * the error e can be lowered by half to 1 / 2^(M+1). By using M bits
 * as the index, each group must contains 2^M buckets.
 *
 * E.g. Let M (FIO_IO_U_PLAT_BITS) be 6
 *      Error bound is 1/2^(6+1) = 0.0078125 (< 1%)
 *
 *	Group	MSB	#discarded	range of		#buckets
 *			error_bits	value
 *	----------------------------------------------------------------
 *	0*	0~5	0		[0,63]			64
 *	1*	6	0		[64,127]		64
 *	2	7	1		[128,255]		64
 *	3	8	2		[256,511]		64
 *	4	9	3		[512,1023]		64
 *	...	...	...		[...,...]		...
 *	18	23	17		[8838608,+inf]**	64
 *
 *  * Special cases: when n < (M-1) or when n == (M-1), in both cases,
 *    the value cannot be rounded off. Use all bits of the sample as
 *    index.
 *
 *  ** If a sample's MSB is greater than 23, it will be counted as 23.
 */

#define FIO_IO_U_PLAT_BITS 6
#define FIO_IO_U_PLAT_VAL (1 << FIO_IO_U_PLAT_BITS)
#define FIO_IO_U_PLAT_GROUP_NR 19
#define FIO_IO_U_PLAT_NR (FIO_IO_U_PLAT_GROUP_NR * FIO_IO_U_PLAT_VAL)
#define FIO_IO_U_LIST_MAX_LEN 20 /* The size of the default and user-specified
					list of percentiles */

#define MAX_PATTERN_SIZE	512
#define FIO_JOBNAME_SIZE	128
#define FIO_JOBDESC_SIZE	256
#define FIO_VERROR_SIZE		128

struct thread_stat {
	char name[FIO_JOBNAME_SIZE];
	char verror[FIO_VERROR_SIZE];
	uint32_t error;
	uint32_t thread_number;
	uint32_t groupid;
	uint32_t pid;
	char description[FIO_JOBDESC_SIZE];
	uint32_t members;
	uint32_t unified_rw_rep;

	/*
	 * bandwidth and latency stats
	 */
	struct io_stat clat_stat[DDIR_RWDIR_CNT]; /* completion latency */
	struct io_stat slat_stat[DDIR_RWDIR_CNT]; /* submission latency */
	struct io_stat lat_stat[DDIR_RWDIR_CNT]; /* total latency */
	struct io_stat bw_stat[DDIR_RWDIR_CNT]; /* bandwidth stats */
	struct io_stat iops_stat[DDIR_RWDIR_CNT]; /* IOPS stats */

	/*
	 * fio system usage accounting
	 */
	uint64_t usr_time;
	uint64_t sys_time;
	uint64_t ctx;
	uint64_t minf, majf;

	/*
	 * IO depth and latency stats
	 */
	uint64_t clat_percentiles;
	uint64_t percentile_precision;
	fio_fp64_t percentile_list[FIO_IO_U_LIST_MAX_LEN];

	uint32_t io_u_map[FIO_IO_U_MAP_NR];
	uint32_t io_u_submit[FIO_IO_U_MAP_NR];
	uint32_t io_u_complete[FIO_IO_U_MAP_NR];
	uint32_t io_u_lat_u[FIO_IO_U_LAT_U_NR];
	uint32_t io_u_lat_m[FIO_IO_U_LAT_M_NR];
	uint32_t io_u_plat[DDIR_RWDIR_CNT][FIO_IO_U_PLAT_NR];
	uint64_t total_io_u[3];
	uint64_t short_io_u[3];
	uint64_t total_submit;
	uint64_t total_complete;

	uint64_t io_bytes[DDIR_RWDIR_CNT];
	uint64_t runtime[DDIR_RWDIR_CNT];
	uint64_t total_run_time;

	/*
	 * IO Error related stats
	 */
	uint16_t continue_on_error;
	uint64_t total_err_count;
	uint32_t first_error;

	uint32_t kb_base;
	uint32_t unit_base;

	uint32_t latency_depth;
	uint64_t latency_target;
	fio_fp64_t latency_percentile;
	uint64_t latency_window;
};

struct jobs_eta {
	uint32_t nr_running;
	uint32_t nr_ramp;
	uint32_t nr_pending;
	uint32_t nr_setting_up;
	uint32_t files_open;
	uint32_t m_rate[DDIR_RWDIR_CNT], t_rate[DDIR_RWDIR_CNT];
	uint32_t m_iops[DDIR_RWDIR_CNT], t_iops[DDIR_RWDIR_CNT];
	uint32_t rate[DDIR_RWDIR_CNT];
	uint32_t iops[DDIR_RWDIR_CNT];
	uint64_t elapsed_sec;
	uint64_t eta_sec;
	uint32_t is_pow2;
	uint32_t unit_base;

	/*
	 * Network 'copy' of run_str[]
	 */
	uint32_t nr_threads;
	uint8_t run_str[];
};

extern void stat_init(void);
extern void stat_exit(void);

extern struct json_object * show_thread_status(struct thread_stat *ts, struct group_run_stats *rs);
extern void show_group_stats(struct group_run_stats *rs);
extern int calc_thread_status(struct jobs_eta *je, int force);
extern void display_thread_status(struct jobs_eta *je);
extern void show_run_stats(void);
extern void show_running_run_stats(void);
extern void check_for_running_stats(void);
extern void sum_thread_stats(struct thread_stat *dst, struct thread_stat *src, int nr);
extern void sum_group_stats(struct group_run_stats *dst, struct group_run_stats *src);
extern void init_thread_stat(struct thread_stat *ts);
extern void init_group_run_stat(struct group_run_stats *gs);
extern void eta_to_str(char *str, unsigned long eta_sec);
extern int calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max, double *mean, double *dev);
extern unsigned int calc_clat_percentiles(unsigned int *io_u_plat, unsigned long nr, fio_fp64_t *plist, unsigned int **output, unsigned int *maxv, unsigned int *minv);
extern void stat_calc_lat_m(struct thread_stat *ts, double *io_u_lat);
extern void stat_calc_lat_u(struct thread_stat *ts, double *io_u_lat);
extern void stat_calc_dist(unsigned int *map, unsigned long total, double *io_u_dist);
extern void reset_io_stats(struct thread_data *);

static inline int usec_to_msec(unsigned long *min, unsigned long *max,
			       double *mean, double *dev)
{
	if (*min > 1000 && *max > 1000 && *mean > 1000.0 && *dev > 1000.0) {
		*min /= 1000;
		*max /= 1000;
		*mean /= 1000.0;
		*dev /= 1000.0;
		return 0;
	}

	return 1;
}

#endif
