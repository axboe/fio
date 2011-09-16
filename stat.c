#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <math.h>

#include "fio.h"
#include "diskutil.h"

void update_rusage_stat(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;

	getrusage(RUSAGE_SELF, &ts->ru_end);

	ts->usr_time += mtime_since(&ts->ru_start.ru_utime,
					&ts->ru_end.ru_utime);
	ts->sys_time += mtime_since(&ts->ru_start.ru_stime,
					&ts->ru_end.ru_stime);
	ts->ctx += ts->ru_end.ru_nvcsw + ts->ru_end.ru_nivcsw
			- (ts->ru_start.ru_nvcsw + ts->ru_start.ru_nivcsw);
	ts->minf += ts->ru_end.ru_minflt - ts->ru_start.ru_minflt;
	ts->majf += ts->ru_end.ru_majflt - ts->ru_start.ru_majflt;

	memcpy(&ts->ru_start, &ts->ru_end, sizeof(ts->ru_end));
}

/*
 * Given a latency, return the index of the corresponding bucket in
 * the structure tracking percentiles.
 *
 * (1) find the group (and error bits) that the value (latency)
 * belongs to by looking at its MSB. (2) find the bucket number in the
 * group by looking at the index bits.
 *
 */
static unsigned int plat_val_to_idx(unsigned int val)
{
	unsigned int msb, error_bits, base, offset, idx;

	/* Find MSB starting from bit 0 */
	if (val == 0)
		msb = 0;
	else
		msb = (sizeof(val)*8) - __builtin_clz(val) - 1;

	/*
	 * MSB <= (FIO_IO_U_PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index
	 */
	if (msb <= FIO_IO_U_PLAT_BITS)
		return val;

	/* Compute the number of error bits to discard*/
	error_bits = msb - FIO_IO_U_PLAT_BITS;

	/* Compute the number of buckets before the group */
	base = (error_bits + 1) << FIO_IO_U_PLAT_BITS;

	/*
	 * Discard the error bits and apply the mask to find the
         * index for the buckets in the group
	 */
	offset = (FIO_IO_U_PLAT_VAL - 1) & (val >> error_bits);

	/* Make sure the index does not exceed (array size - 1) */
	idx = (base + offset) < (FIO_IO_U_PLAT_NR - 1)?
		(base + offset) : (FIO_IO_U_PLAT_NR - 1);

	return idx;
}

/*
 * Convert the given index of the bucket array to the value
 * represented by the bucket
 */
static unsigned int plat_idx_to_val(unsigned int idx)
{
	unsigned int error_bits, k, base;

	assert(idx < FIO_IO_U_PLAT_NR);

	/* MSB <= (FIO_IO_U_PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index */
	if (idx < (FIO_IO_U_PLAT_VAL << 1) )
		return idx;

	/* Find the group and compute the minimum value of that group */
	error_bits = (idx >> FIO_IO_U_PLAT_BITS) -1;
	base = 1 << (error_bits + FIO_IO_U_PLAT_BITS);

	/* Find its bucket number of the group */
	k = idx % FIO_IO_U_PLAT_VAL;

	/* Return the mean of the range of the bucket */
	return base + ((k + 0.5) * (1 << error_bits));
}

static int double_cmp(const void *a, const void *b)
{
	const double fa = *(const double *)a;
	const double fb = *(const double *)b;
	int cmp = 0;

	if (fa > fb)
		cmp = 1;
	else if (fa < fb)
		cmp = -1;

	return cmp;
}

/*
 * Find and display the p-th percentile of clat
 */
static void show_clat_percentiles(unsigned int* io_u_plat, unsigned long nr,
				 double* user_list)
{
	unsigned long sum = 0;
	unsigned int len, i, j = 0;
	const double *plist;
	int is_last = 0;
	static const double def_list[FIO_IO_U_LIST_MAX_LEN] = {
			1.0, 5.0, 10.0, 20.0, 30.0,
			40.0, 50.0, 60.0, 70.0, 80.0,
			90.0, 95.0, 99.0, 99.5, 99.9};

	plist = user_list;
	if (!plist)
		plist = def_list;

	for (len = 0; len <FIO_IO_U_LIST_MAX_LEN && plist[len] != 0; len++)
		;

	/*
	 * Sort the user-specified list. Note that this does not work
	 * for NaN values
	 */
	if (user_list && len > 1)
		qsort((void*)user_list, len, sizeof(user_list[0]), double_cmp);

	log_info("    clat percentiles (usec) :");

	for (i = 0; i < FIO_IO_U_PLAT_NR && !is_last; i++) {
		sum += io_u_plat[i];
		while (sum >= (plist[j] / 100 * nr)) {
			assert(plist[j] <= 100.0);

			/* for formatting */
			if (j != 0 && (j % 4) == 0)
				log_info("                             ");

			/* end of the list */
			is_last = (j == len - 1);

			log_info(" %2.2fth=%u%c", plist[j], plat_idx_to_val(i),
				 (is_last? '\n' : ','));

			if (is_last)
				break;

			if (j % 4 == 3)	/* for formatting */
				log_info("\n");
			j++;
		}
	}
}

static int calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max,
		    double *mean, double *dev)
{
	double n = is->samples;

	if (is->samples == 0)
		return 0;

	*min = is->min_val;
	*max = is->max_val;

	n = (double) is->samples;
	*mean = is->mean;

	if (n > 1.0)
		*dev = sqrt(is->S / (n - 1.0));
	else
		*dev = 0;

	return 1;
}

static void show_group_stats(struct group_run_stats *rs, int id)
{
	char *p1, *p2, *p3, *p4;
	const char *ddir_str[] = { "   READ", "  WRITE" };
	int i;

	log_info("\nRun status group %d (all jobs):\n", id);

	for (i = 0; i <= DDIR_WRITE; i++) {
		const int i2p = is_power_of_2(rs->kb_base);

		if (!rs->max_run[i])
			continue;

		p1 = num2str(rs->io_kb[i], 6, rs->kb_base, i2p);
		p2 = num2str(rs->agg[i], 6, rs->kb_base, i2p);
		p3 = num2str(rs->min_bw[i], 6, rs->kb_base, i2p);
		p4 = num2str(rs->max_bw[i], 6, rs->kb_base, i2p);

		log_info("%s: io=%sB, aggrb=%sB/s, minb=%sB/s, maxb=%sB/s,"
			 " mint=%llumsec, maxt=%llumsec\n", ddir_str[i], p1, p2,
						p3, p4, rs->min_run[i],
						rs->max_run[i]);

		free(p1);
		free(p2);
		free(p3);
		free(p4);
	}
}

#define ts_total_io_u(ts)	\
	((ts)->total_io_u[0] + (ts)->total_io_u[1])

static void stat_calc_dist(unsigned int *map, unsigned long total,
			   double *io_u_dist)
{
	int i;

	/*
	 * Do depth distribution calculations
	 */
	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		if (total) {
			io_u_dist[i] = (double) map[i] / (double) total;
			io_u_dist[i] *= 100.0;
			if (io_u_dist[i] < 0.1 && map[i])
				io_u_dist[i] = 0.1;
		} else
			io_u_dist[i] = 0.0;
	}
}

static void stat_calc_lat(struct thread_stat *ts, double *dst,
			  unsigned int *src, int nr)
{
	unsigned long total = ts_total_io_u(ts);
	int i;

	/*
	 * Do latency distribution calculations
	 */
	for (i = 0; i < nr; i++) {
		if (total) {
			dst[i] = (double) src[i] / (double) total;
			dst[i] *= 100.0;
			if (dst[i] < 0.01 && src[i])
				dst[i] = 0.01;
		} else
			dst[i] = 0.0;
	}
}

static void stat_calc_lat_u(struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_u, FIO_IO_U_LAT_U_NR);
}

static void stat_calc_lat_m(struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_m, FIO_IO_U_LAT_M_NR);
}

static int usec_to_msec(unsigned long *min, unsigned long *max, double *mean,
			double *dev)
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

static void show_ddir_status(struct group_run_stats *rs, struct thread_stat *ts,
			     int ddir)
{
	const char *ddir_str[] = { "read ", "write" };
	unsigned long min, max, runt;
	unsigned long long bw, iops;
	double mean, dev;
	char *io_p, *bw_p, *iops_p;
	int i2p;

	assert(ddir_rw(ddir));

	if (!ts->runtime[ddir])
		return;

	i2p = is_power_of_2(rs->kb_base);
	runt = ts->runtime[ddir];

	bw = (1000 * ts->io_bytes[ddir]) / runt;
	io_p = num2str(ts->io_bytes[ddir], 6, 1, i2p);
	bw_p = num2str(bw, 6, 1, i2p);

	iops = (1000 * (uint64_t)ts->total_io_u[ddir]) / runt;
	iops_p = num2str(iops, 6, 1, 0);

	log_info("  %s: io=%sB, bw=%sB/s, iops=%s, runt=%6llumsec\n",
					ddir_str[ddir], io_p, bw_p, iops_p,
					ts->runtime[ddir]);

	free(io_p);
	free(bw_p);
	free(iops_p);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev)) {
		const char *base = "(usec)";
		char *minp, *maxp;

		if (!usec_to_msec(&min, &max, &mean, &dev))
			base = "(msec)";

		minp = num2str(min, 6, 1, 0);
		maxp = num2str(max, 6, 1, 0);

		log_info("    slat %s: min=%s, max=%s, avg=%5.02f,"
			 " stdev=%5.02f\n", base, minp, maxp, mean, dev);

		free(minp);
		free(maxp);
	}
	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev)) {
		const char *base = "(usec)";
		char *minp, *maxp;

		if (!usec_to_msec(&min, &max, &mean, &dev))
			base = "(msec)";

		minp = num2str(min, 6, 1, 0);
		maxp = num2str(max, 6, 1, 0);

		log_info("    clat %s: min=%s, max=%s, avg=%5.02f,"
			 " stdev=%5.02f\n", base, minp, maxp, mean, dev);

		free(minp);
		free(maxp);
	}
	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev)) {
		const char *base = "(usec)";
		char *minp, *maxp;

		if (!usec_to_msec(&min, &max, &mean, &dev))
			base = "(msec)";

		minp = num2str(min, 6, 1, 0);
		maxp = num2str(max, 6, 1, 0);

		log_info("     lat %s: min=%s, max=%s, avg=%5.02f,"
			 " stdev=%5.02f\n", base, minp, maxp, mean, dev);

		free(minp);
		free(maxp);
	}
	if (ts->clat_percentiles) {
		show_clat_percentiles(ts->io_u_plat[ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list);
	}
	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		log_info("    bw (KB/s) : min=%5lu, max=%5lu, per=%3.2f%%,"
			 " avg=%5.02f, stdev=%5.02f\n", min, max, p_of_agg,
							mean, dev);
	}
}

static void show_lat(double *io_u_lat, int nr, const char **ranges,
		     const char *msg)
{
	int new_line = 1, i, line = 0;

	for (i = 0; i < nr; i++) {
		if (io_u_lat[i] <= 0.0)
			continue;
		if (new_line) {
			if (line)
				log_info("\n");
			log_info("     lat (%s): ", msg);
			new_line = 0;
			line = 0;
		}
		if (line)
			log_info(", ");
		log_info("%s%3.2f%%", ranges[i], io_u_lat[i]);
		line++;
		if (line == 5)
			new_line = 1;
	}
}

static void show_lat_u(double *io_u_lat_u)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", };

	show_lat(io_u_lat_u, FIO_IO_U_LAT_U_NR, ranges, "usec");
}

static void show_lat_m(double *io_u_lat_m)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", "2000=",
				 ">=2000=", };

	show_lat(io_u_lat_m, FIO_IO_U_LAT_M_NR, ranges, "msec");
}

static void show_latencies(double *io_u_lat_u, double *io_u_lat_m)
{
	show_lat_u(io_u_lat_u);
	log_info("\n");
	show_lat_m(io_u_lat_m);
	log_info("\n");
}

static void show_thread_status(struct thread_stat *ts,
			       struct group_run_stats *rs)
{
	double usr_cpu, sys_cpu;
	unsigned long runtime;
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];

	if (!(ts->io_bytes[0] + ts->io_bytes[1]) &&
	    !(ts->total_io_u[0] + ts->total_io_u[1]))
		return;

	if (!ts->error) {
		log_info("%s: (groupid=%d, jobs=%d): err=%2d: pid=%d\n",
					ts->name, ts->groupid, ts->members,
					ts->error, (int) ts->pid);
	} else {
		log_info("%s: (groupid=%d, jobs=%d): err=%2d (%s): pid=%d\n",
					ts->name, ts->groupid, ts->members,
					ts->error, ts->verror, (int) ts->pid);
	}

	if (ts->description)
		log_info("  Description  : [%s]\n", ts->description);

	if (ts->io_bytes[DDIR_READ])
		show_ddir_status(rs, ts, DDIR_READ);
	if (ts->io_bytes[DDIR_WRITE])
		show_ddir_status(rs, ts, DDIR_WRITE);

	runtime = ts->total_run_time;
	if (runtime) {
		double runt = (double) runtime;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	log_info("  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%lu, majf=%lu,"
		 " minf=%lu\n", usr_cpu, sys_cpu, ts->ctx, ts->majf, ts->minf);

	stat_calc_dist(ts->io_u_map, ts_total_io_u(ts), io_u_dist);
	log_info("  IO depths    : 1=%3.1f%%, 2=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%,"
		 " 16=%3.1f%%, 32=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);

	stat_calc_dist(ts->io_u_submit, ts->total_submit, io_u_dist);
	log_info("     submit    : 0=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%,"
		 " 32=%3.1f%%, 64=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);
	stat_calc_dist(ts->io_u_complete, ts->total_complete, io_u_dist);
	log_info("     complete  : 0=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%,"
		 " 32=%3.1f%%, 64=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);
	log_info("     issued r/w/d: total=%lu/%lu/%lu, short=%lu/%lu/%lu\n",
					ts->total_io_u[0], ts->total_io_u[1],
					ts->total_io_u[2],
					ts->short_io_u[0], ts->short_io_u[1],
					ts->short_io_u[2]);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);
	show_latencies(io_u_lat_u, io_u_lat_m);
	if (ts->continue_on_error) {
		log_info("     errors    : total=%lu, first_error=%d/<%s>\n",
					ts->total_err_count,
					ts->first_error,
					strerror(ts->first_error));
	}
}

static void show_ddir_status_terse(struct thread_stat *ts,
				   struct group_run_stats *rs, int ddir)
{
	unsigned long min, max;
	unsigned long long bw;
	double mean, dev;

	assert(ddir_rw(ddir));

	bw = 0;
	if (ts->runtime[ddir])
		bw = ts->io_bytes[ddir] / ts->runtime[ddir];

	log_info(";%llu;%llu;%llu", ts->io_bytes[ddir] >> 10, bw,
							ts->runtime[ddir]);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		log_info(";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_info(";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		log_info(";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_info(";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev))
		log_info(";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_info(";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		log_info(";%lu;%lu;%f%%;%f;%f", min, max, p_of_agg, mean, dev);
	} else
		log_info(";%lu;%lu;%f%%;%f;%f", 0UL, 0UL, 0.0, 0.0, 0.0);
}

#define FIO_TERSE_VERSION	"2"

static void show_thread_status_terse(struct thread_stat *ts,
				     struct group_run_stats *rs)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;

	/* General Info */
	log_info("%s;%s;%d;%d", FIO_TERSE_VERSION, ts->name, ts->groupid,
				ts->error);
	/* Log Read Status */
	show_ddir_status_terse(ts, rs, 0);
	/* Log Write Status */
	show_ddir_status_terse(ts, rs, 1);

	/* CPU Usage */
	if (ts->total_run_time) {
		double runt = (double) ts->total_run_time;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	log_info(";%f%%;%f%%;%lu;%lu;%lu", usr_cpu, sys_cpu, ts->ctx, ts->majf,
								ts->minf);

	/* Calc % distribution of IO depths, usecond, msecond latency */
	stat_calc_dist(ts->io_u_map, ts_total_io_u(ts), io_u_dist);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	/* Only show fixed 7 I/O depth levels*/
	log_info(";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%",
			io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3],
			io_u_dist[4], io_u_dist[5], io_u_dist[6]);

	/* Microsecond latency */
	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++)
		log_info(";%3.2f%%", io_u_lat_u[i]);
	/* Millisecond latency */
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++)
		log_info(";%3.2f%%", io_u_lat_m[i]);
	/* Additional output if continue_on_error set - default off*/
	if (ts->continue_on_error)
		log_info(";%lu;%d", ts->total_err_count, ts->first_error);
	log_info("\n");

	/* Additional output if description is set */
	if (ts->description)
		log_info(";%s", ts->description);

	log_info("\n");
}

static void sum_stat(struct io_stat *dst, struct io_stat *src, int nr)
{
	double mean, S;

	if (src->samples == 0)
		return;

	dst->min_val = min(dst->min_val, src->min_val);
	dst->max_val = max(dst->max_val, src->max_val);

	/*
	 * Compute new mean and S after the merge
	 * <http://en.wikipedia.org/wiki/Algorithms_for_calculating_variance
	 *  #Parallel_algorithm>
	 */
	if (nr == 1) {
		mean = src->mean;
		S = src->S;
	} else {
		double delta = src->mean - dst->mean;

		mean = ((src->mean * src->samples) +
			(dst->mean * dst->samples)) /
			(dst->samples + src->samples);

		S =  src->S + dst->S + pow(delta, 2.0) *
			(dst->samples * src->samples) /
			(dst->samples + src->samples);
	}

	dst->samples += src->samples;
	dst->mean = mean;
	dst->S = S;
}

void show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	struct thread_stat *threadstats, *ts;
	int i, j, k, l, nr_ts, last_ts, idx;
	int kb_base_warned = 0;

	runstats = malloc(sizeof(struct group_run_stats) * (groupid + 1));

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		memset(rs, 0, sizeof(*rs));
		rs->min_bw[0] = rs->min_run[0] = ~0UL;
		rs->min_bw[1] = rs->min_run[1] = ~0UL;
	}

	/*
	 * find out how many threads stats we need. if group reporting isn't
	 * enabled, it's one-per-td.
	 */
	nr_ts = 0;
	last_ts = -1;
	for_each_td(td, i) {
		if (!td->o.group_reporting) {
			nr_ts++;
			continue;
		}
		if (last_ts == td->groupid)
			continue;

		last_ts = td->groupid;
		nr_ts++;
	}

	threadstats = malloc(nr_ts * sizeof(struct thread_stat));

	for (i = 0; i < nr_ts; i++) {
		ts = &threadstats[i];

		memset(ts, 0, sizeof(*ts));
		for (j = 0; j <= DDIR_WRITE; j++) {
			ts->lat_stat[j].min_val = -1UL;
			ts->clat_stat[j].min_val = -1UL;
			ts->slat_stat[j].min_val = -1UL;
			ts->bw_stat[j].min_val = -1UL;
		}
		ts->groupid = -1;
	}

	j = 0;
	last_ts = -1;
	idx = 0;
	for_each_td(td, i) {
		if (idx && (!td->o.group_reporting ||
		    (td->o.group_reporting && last_ts != td->groupid))) {
			idx = 0;
			j++;
		}

		last_ts = td->groupid;

		ts = &threadstats[j];

		ts->clat_percentiles = td->o.clat_percentiles;
		if (td->o.overwrite_plist)
			ts->percentile_list = td->o.percentile_list;
		else
			ts->percentile_list = NULL;

		idx++;
		ts->members++;

		if (ts->groupid == -1) {
			/*
			 * These are per-group shared already
			 */
			ts->name = td->o.name;
			ts->description = td->o.description;
			ts->groupid = td->groupid;

			/*
			 * first pid in group, not very useful...
			 */
			ts->pid = td->pid;

			ts->kb_base = td->o.kb_base;
		} else if (ts->kb_base != td->o.kb_base && !kb_base_warned) {
			log_info("fio: kb_base differs for jobs in group, using"
				 " %u as the base\n", ts->kb_base);
			kb_base_warned = 1;
		}

		ts->continue_on_error = td->o.continue_on_error;
		ts->total_err_count += td->total_err_count;
		ts->first_error = td->first_error;
		if (!ts->error) {
			if (!td->error && td->o.continue_on_error &&
			    td->first_error) {
				ts->error = td->first_error;
				ts->verror = td->verror;
			} else  if (td->error) {
				ts->error = td->error;
				ts->verror = td->verror;
			}
		}

		for (l = 0; l <= DDIR_WRITE; l++) {
			sum_stat(&ts->clat_stat[l], &td->ts.clat_stat[l], idx);
			sum_stat(&ts->slat_stat[l], &td->ts.slat_stat[l], idx);
			sum_stat(&ts->lat_stat[l], &td->ts.lat_stat[l], idx);
			sum_stat(&ts->bw_stat[l], &td->ts.bw_stat[l], idx);

			ts->stat_io_bytes[l] += td->ts.stat_io_bytes[l];
			ts->io_bytes[l] += td->ts.io_bytes[l];

			if (ts->runtime[l] < td->ts.runtime[l])
				ts->runtime[l] = td->ts.runtime[l];
		}

		ts->usr_time += td->ts.usr_time;
		ts->sys_time += td->ts.sys_time;
		ts->ctx += td->ts.ctx;
		ts->majf += td->ts.majf;
		ts->minf += td->ts.minf;

		for (k = 0; k < FIO_IO_U_MAP_NR; k++)
			ts->io_u_map[k] += td->ts.io_u_map[k];
		for (k = 0; k < FIO_IO_U_MAP_NR; k++)
			ts->io_u_submit[k] += td->ts.io_u_submit[k];
		for (k = 0; k < FIO_IO_U_MAP_NR; k++)
			ts->io_u_complete[k] += td->ts.io_u_complete[k];
		for (k = 0; k < FIO_IO_U_LAT_U_NR; k++)
			ts->io_u_lat_u[k] += td->ts.io_u_lat_u[k];
		for (k = 0; k < FIO_IO_U_LAT_M_NR; k++)
			ts->io_u_lat_m[k] += td->ts.io_u_lat_m[k];


		for (k = 0; k <= 2; k++) {
			ts->total_io_u[k] += td->ts.total_io_u[k];
			ts->short_io_u[k] += td->ts.short_io_u[k];
		}

		for (k = 0; k <= DDIR_WRITE; k++) {
			int m;
			for (m = 0; m < FIO_IO_U_PLAT_NR; m++)
				ts->io_u_plat[k][m] += td->ts.io_u_plat[k][m];
		}

		ts->total_run_time += td->ts.total_run_time;
		ts->total_submit += td->ts.total_submit;
		ts->total_complete += td->ts.total_complete;
	}

	for (i = 0; i < nr_ts; i++) {
		unsigned long long bw;

		ts = &threadstats[i];
		rs = &runstats[ts->groupid];
		rs->kb_base = ts->kb_base;

		for (j = 0; j <= DDIR_WRITE; j++) {
			if (!ts->runtime[j])
				continue;
			if (ts->runtime[j] < rs->min_run[j] || !rs->min_run[j])
				rs->min_run[j] = ts->runtime[j];
			if (ts->runtime[j] > rs->max_run[j])
				rs->max_run[j] = ts->runtime[j];

			bw = 0;
			if (ts->runtime[j]) {
				unsigned long runt;

				runt = ts->runtime[j];
				bw = ts->io_bytes[j] / runt;
			}
			if (bw < rs->min_bw[j])
				rs->min_bw[j] = bw;
			if (bw > rs->max_bw[j])
				rs->max_bw[j] = bw;

			rs->io_kb[j] += ts->io_bytes[j] / rs->kb_base;
		}
	}

	for (i = 0; i < groupid + 1; i++) {
		unsigned long max_run[2];

		rs = &runstats[i];
		max_run[0] = rs->max_run[0];
		max_run[1] = rs->max_run[1];

		if (rs->max_run[0])
			rs->agg[0] = (rs->io_kb[0] * 1000) / max_run[0];
		if (rs->max_run[1])
			rs->agg[1] = (rs->io_kb[1] * 1000) / max_run[1];
	}

	/*
	 * don't overwrite last signal output
	 */
	if (!terse_output)
		log_info("\n");

	for (i = 0; i < nr_ts; i++) {
		ts = &threadstats[i];
		rs = &runstats[ts->groupid];

		if (terse_output)
			show_thread_status_terse(ts, rs);
		else
			show_thread_status(ts, rs);
	}

	if (!terse_output) {
		for (i = 0; i < groupid + 1; i++)
			show_group_stats(&runstats[i], i);

		show_disk_util();
	}

	free(runstats);
	free(threadstats);
}

static inline void add_stat_sample(struct io_stat *is, unsigned long data)
{
	double val = data;
	double delta;

	if (data > is->max_val)
		is->max_val = data;
	if (data < is->min_val)
		is->min_val = data;

	delta = val - is->mean;
	if (delta) {
		is->mean += delta / (is->samples + 1.0);
		is->S += delta * (val - is->mean);
	}

	is->samples++;
}

static void __add_log_sample(struct io_log *iolog, unsigned long val,
			     enum fio_ddir ddir, unsigned int bs,
			     unsigned long t)
{
	const int nr_samples = iolog->nr_samples;

	if (iolog->nr_samples == iolog->max_samples) {
		int new_size = sizeof(struct io_sample) * iolog->max_samples*2;

		iolog->log = realloc(iolog->log, new_size);
		iolog->max_samples <<= 1;
	}

	iolog->log[nr_samples].val = val;
	iolog->log[nr_samples].time = t;
	iolog->log[nr_samples].ddir = ddir;
	iolog->log[nr_samples].bs = bs;
	iolog->nr_samples++;
}

static void add_log_sample(struct thread_data *td, struct io_log *iolog,
			   unsigned long val, enum fio_ddir ddir,
			   unsigned int bs)
{
	if (!ddir_rw(ddir))
		return;

	__add_log_sample(iolog, val, ddir, bs, mtime_since_now(&td->epoch));
}

void add_agg_sample(unsigned long val, enum fio_ddir ddir, unsigned int bs)
{
	struct io_log *iolog;

	if (!ddir_rw(ddir))
		return;

	iolog = agg_io_log[ddir];
	__add_log_sample(iolog, val, ddir, bs, mtime_since_genesis());
}

static void add_clat_percentile_sample(struct thread_stat *ts,
				unsigned long usec, enum fio_ddir ddir)
{
	unsigned int idx = plat_val_to_idx(usec);
	assert(idx < FIO_IO_U_PLAT_NR);

	ts->io_u_plat[ddir][idx]++;
}

void add_clat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec, unsigned int bs)
{
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	add_stat_sample(&ts->clat_stat[ddir], usec);

	if (ts->clat_log)
		add_log_sample(td, ts->clat_log, usec, ddir, bs);

	if (ts->clat_percentiles)
		add_clat_percentile_sample(ts, usec, ddir);
}

void add_slat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec, unsigned int bs)
{
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	add_stat_sample(&ts->slat_stat[ddir], usec);

	if (ts->slat_log)
		add_log_sample(td, ts->slat_log, usec, ddir, bs);
}

void add_lat_sample(struct thread_data *td, enum fio_ddir ddir,
		    unsigned long usec, unsigned int bs)
{
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	add_stat_sample(&ts->lat_stat[ddir], usec);

	if (ts->lat_log)
		add_log_sample(td, ts->lat_log, usec, ddir, bs);
}

void add_bw_sample(struct thread_data *td, enum fio_ddir ddir, unsigned int bs,
		   struct timeval *t)
{
	struct thread_stat *ts = &td->ts;
	unsigned long spent, rate;

	if (!ddir_rw(ddir))
		return;

	spent = mtime_since(&ts->stat_sample_time[ddir], t);
	if (spent < td->o.bw_avg_time)
		return;

	rate = (td->this_io_bytes[ddir] - ts->stat_io_bytes[ddir]) *
			1000 / spent / 1024;
	add_stat_sample(&ts->bw_stat[ddir], rate);

	if (ts->bw_log)
		add_log_sample(td, ts->bw_log, rate, ddir, bs);

	fio_gettime(&ts->stat_sample_time[ddir], NULL);
	ts->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
}
