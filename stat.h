#ifndef FIO_STAT_H
#define FIO_STAT_H

#include "iolog.h"
#include "lib/output_buffer.h"

struct group_run_stats {
	uint64_t max_run[DDIR_RWDIR_CNT], min_run[DDIR_RWDIR_CNT];
	uint64_t max_bw[DDIR_RWDIR_CNT], min_bw[DDIR_RWDIR_CNT];
	uint64_t iobytes[DDIR_RWDIR_CNT];
	uint64_t agg[DDIR_RWDIR_CNT];
	uint32_t kb_base;
	uint32_t unit_base;
	uint32_t groupid;
	uint32_t unified_rw_rep;
} __attribute__((packed));

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

/*
 * Trim cycle count measurements
 */
#define MAX_NR_BLOCK_INFOS	8192
#define BLOCK_INFO_STATE_SHIFT	29
#define BLOCK_INFO_TRIMS(block_info)	\
	((block_info) & ((1 << BLOCK_INFO_STATE_SHIFT) - 1))
#define BLOCK_INFO_STATE(block_info)		\
	((block_info) >> BLOCK_INFO_STATE_SHIFT)
#define BLOCK_INFO(state, trim_cycles)	\
	((trim_cycles) | ((unsigned int) (state) << BLOCK_INFO_STATE_SHIFT))
#define BLOCK_INFO_SET_STATE(block_info, state)	\
	BLOCK_INFO(state, BLOCK_INFO_TRIMS(block_info))
enum block_info_state {
	BLOCK_STATE_UNINIT,
	BLOCK_STATE_TRIMMED,
	BLOCK_STATE_WRITTEN,
	BLOCK_STATE_TRIM_FAILURE,
	BLOCK_STATE_WRITE_FAILURE,
	BLOCK_STATE_COUNT,
};

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
	uint32_t pad;

	uint64_t total_io_u[DDIR_RWDIR_CNT];
	uint64_t short_io_u[DDIR_RWDIR_CNT];
	uint64_t drop_io_u[DDIR_RWDIR_CNT];
	uint64_t total_submit;
	uint64_t total_complete;

	uint64_t io_bytes[DDIR_RWDIR_CNT];
	uint64_t runtime[DDIR_RWDIR_CNT];
	uint64_t total_run_time;

	/*
	 * IO Error related stats
	 */
	union {
		uint16_t continue_on_error;
		uint32_t pad2;
	};
	uint32_t first_error;
	uint64_t total_err_count;

	uint64_t nr_block_infos;
	uint32_t block_infos[MAX_NR_BLOCK_INFOS];

	uint32_t kb_base;
	uint32_t unit_base;

	uint32_t latency_depth;
	uint32_t pad3;
	uint64_t latency_target;
	fio_fp64_t latency_percentile;
	uint64_t latency_window;

	uint64_t ss_dur;
	uint32_t ss_state;
	uint32_t ss_head;

	fio_fp64_t ss_limit;
	fio_fp64_t ss_slope;
	fio_fp64_t ss_deviation;
	fio_fp64_t ss_criterion;

	union {
		uint64_t *ss_iops_data;
		uint64_t pad4;
	};

	union {
		uint64_t *ss_bw_data;
		uint64_t pad5;
	};
} __attribute__((packed));

struct jobs_eta {
	uint32_t nr_running;
	uint32_t nr_ramp;

	uint32_t nr_pending;
	uint32_t nr_setting_up;

	uint32_t files_open;

	uint64_t m_rate[DDIR_RWDIR_CNT], t_rate[DDIR_RWDIR_CNT];
	uint32_t m_iops[DDIR_RWDIR_CNT], t_iops[DDIR_RWDIR_CNT];
	uint64_t rate[DDIR_RWDIR_CNT];
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
} __attribute__((packed));

struct io_u_plat_entry {
	struct flist_head list;
	unsigned int io_u_plat[FIO_IO_U_PLAT_NR];
};

extern struct fio_mutex *stat_mutex;

extern struct jobs_eta *get_jobs_eta(bool force, size_t *size);

extern void stat_init(void);
extern void stat_exit(void);

extern struct json_object * show_thread_status(struct thread_stat *ts, struct group_run_stats *rs, struct flist_head *, struct buf_output *);
extern void show_group_stats(struct group_run_stats *rs, struct buf_output *);
extern bool calc_thread_status(struct jobs_eta *je, int force);
extern void display_thread_status(struct jobs_eta *je);
extern void show_run_stats(void);
extern void __show_run_stats(void);
extern void __show_running_run_stats(void);
extern void show_running_run_stats(void);
extern void check_for_running_stats(void);
extern void sum_thread_stats(struct thread_stat *dst, struct thread_stat *src, bool first);
extern void sum_group_stats(struct group_run_stats *dst, struct group_run_stats *src);
extern void init_thread_stat(struct thread_stat *ts);
extern void init_group_run_stat(struct group_run_stats *gs);
extern void eta_to_str(char *str, unsigned long eta_sec);
extern bool calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max, double *mean, double *dev);
extern unsigned int calc_clat_percentiles(unsigned int *io_u_plat, unsigned long nr, fio_fp64_t *plist, unsigned int **output, unsigned int *maxv, unsigned int *minv);
extern void stat_calc_lat_m(struct thread_stat *ts, double *io_u_lat);
extern void stat_calc_lat_u(struct thread_stat *ts, double *io_u_lat);
extern void stat_calc_dist(unsigned int *map, unsigned long total, double *io_u_dist);
extern void reset_io_stats(struct thread_data *);
extern void update_rusage_stat(struct thread_data *);
extern void clear_rusage_stat(struct thread_data *);

extern void add_lat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int, uint64_t);
extern void add_clat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int, uint64_t);
extern void add_slat_sample(struct thread_data *, enum fio_ddir, unsigned long,
				unsigned int, uint64_t);
extern void add_agg_sample(union io_sample_data, enum fio_ddir, unsigned int);
extern void add_iops_sample(struct thread_data *, struct io_u *,
				unsigned int);
extern void add_bw_sample(struct thread_data *, struct io_u *,
				unsigned int, unsigned long);
extern int calc_log_samples(void);

extern struct io_log *agg_io_log[DDIR_RWDIR_CNT];
extern int write_bw_log;

static inline bool usec_to_msec(unsigned long *min, unsigned long *max,
				double *mean, double *dev)
{
	if (*min > 1000 && *max > 1000 && *mean > 1000.0 && *dev > 1000.0) {
		*min /= 1000;
		*max /= 1000;
		*mean /= 1000.0;
		*dev /= 1000.0;
		return true;
	}

	return false;
}
/*
 * Worst level condensing would be 1:5, so allow enough room for that
 */
#define __THREAD_RUNSTR_SZ(nr)	((nr) * 5)
#define THREAD_RUNSTR_SZ	__THREAD_RUNSTR_SZ(thread_number)

uint32_t *io_u_block_info(struct thread_data *td, struct io_u *io_u);

#endif
