#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <math.h>

#include "fio.h"

/*
 * Cheesy number->string conversion, complete with carry rounding error.
 */
static char *num2str(unsigned long num, int maxlen, int base, int pow2)
{
	char postfix[] = { ' ', 'K', 'M', 'G', 'P', 'E' };
	unsigned int thousand;
	char *buf;
	int i;

	if (pow2)
		thousand = 1024;
	else
		thousand = 1000;

	buf = malloc(128);

	for (i = 0; base > 1; i++)
		base /= thousand;

	do {
		int len, carry = 0;

		len = sprintf(buf, "%'lu", num);
		if (len <= maxlen) {
			if (i >= 1) {
				buf[len] = postfix[i];
				buf[len + 1] = '\0';
			}
			return buf;
		}

		if ((num % thousand) >= (thousand / 2))
			carry = 1;

		num /= thousand;
		num += carry;
		i++;
	} while (i <= 5);

	return buf;
}

void update_rusage_stat(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;

	getrusage(RUSAGE_SELF, &ts->ru_end);

	ts->usr_time += mtime_since(&ts->ru_start.ru_utime, &ts->ru_end.ru_utime);
	ts->sys_time += mtime_since(&ts->ru_start.ru_stime, &ts->ru_end.ru_stime);
	ts->ctx += ts->ru_end.ru_nvcsw + ts->ru_end.ru_nivcsw - (ts->ru_start.ru_nvcsw + ts->ru_start.ru_nivcsw);
	
	memcpy(&ts->ru_start, &ts->ru_end, sizeof(ts->ru_end));
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
		*dev = -1.0;

	return 1;
}

static void show_group_stats(struct group_run_stats *rs, int id)
{
	char *p1, *p2, *p3, *p4;
	const char *ddir_str[] = { "   READ", "  WRITE" };
	int i;

	log_info("\nRun status group %d (all jobs):\n", id);

	for (i = 0; i <= DDIR_WRITE; i++) {
		if (!rs->max_run[i])
			continue;

		p1 = num2str(rs->io_kb[i], 6, 1000, 1);
		p2 = num2str(rs->agg[i], 6, 1000, 1);
		p3 = num2str(rs->min_bw[i], 6, 1000, 1);
		p4 = num2str(rs->max_bw[i], 6, 1000, 1);

		log_info("%s: io=%siB, aggrb=%siB/s, minb=%siB/s, maxb=%siB/s, mint=%llumsec, maxt=%llumsec\n", ddir_str[i], p1, p2, p3, p4, rs->min_run[i], rs->max_run[i]);

		free(p1);
		free(p2);
		free(p3);
		free(p4);
	}
}

#define ts_total_io_u(ts)	\
	((ts)->total_io_u[0] + (ts)->total_io_u[1])

static void stat_calc_dist(struct thread_stat *ts, double *io_u_dist)
{
	int i;

	/*
	 * Do depth distribution calculations
	 */
	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		io_u_dist[i] = (double) ts->io_u_map[i] / (double) ts_total_io_u(ts);
		io_u_dist[i] *= 100.0;
		if (io_u_dist[i] < 0.1 && ts->io_u_map[i])
			io_u_dist[i] = 0.1;
	}
}

static void stat_calc_lat(struct thread_stat *ts, double *dst,
			  unsigned int *src, int nr)
{
	int i;

	/*
	 * Do latency distribution calculations
	 */
	for (i = 0; i < nr; i++) {
		dst[i] = (double) src[i] / (double) ts_total_io_u(ts);
		dst[i] *= 100.0;
		if (dst[i] < 0.01 && src[i])
			dst[i] = 0.01;
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
	unsigned long min, max;
	unsigned long long bw, iops;
	double mean, dev;
	char *io_p, *bw_p, *iops_p;

	if (!ts->runtime[ddir])
		return;

	bw = ts->io_bytes[ddir] / ts->runtime[ddir];
	iops = (1000 * ts->total_io_u[ddir]) / ts->runtime[ddir];
	io_p = num2str(ts->io_bytes[ddir] >> 10, 6, 1000, 1);
	bw_p = num2str(bw, 6, 1000, 1);
	iops_p = num2str(iops, 6, 1, 0);

	log_info("  %s: io=%siB, bw=%siB/s, iops=%s, runt=%6lumsec\n", ddir_str[ddir], io_p, bw_p, iops_p, ts->runtime[ddir]);

	free(io_p);
	free(bw_p);
	free(iops_p);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev)) {
		const char *base = "(usec)";

		if (!usec_to_msec(&min, &max, &mean, &dev))
			base = "(msec)";

		log_info("    slat %s: min=%5lu, max=%5lu, avg=%5.02f, stdev=%5.02f\n", base, min, max, mean, dev);
	}
	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev)) {
		const char *base = "(usec)";

		if (!usec_to_msec(&min, &max, &mean, &dev))
			base = "(msec)";

		log_info("    clat %s: min=%5lu, max=%5lu, avg=%5.02f, stdev=%5.02f\n", base, min, max, mean, dev);
	}
	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		log_info("    bw (KiB/s) : min=%5lu, max=%5lu, per=%3.2f%%, avg=%5.02f, stdev=%5.02f\n", min, max, p_of_agg, mean, dev);
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

	if (!(ts->io_bytes[0] + ts->io_bytes[1]))
		return;

	if (!ts->error)
		log_info("%s: (groupid=%d, jobs=%d): err=%2d: pid=%d\n", ts->name, ts->groupid, ts->members, ts->error, ts->pid);
	else
		log_info("%s: (groupid=%d, jobs=%d): err=%2d (%s): pid=%d\n", ts->name, ts->groupid, ts->members, ts->error, ts->verror, ts->pid);

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

	log_info("  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%lu\n", usr_cpu, sys_cpu, ts->ctx);

	stat_calc_dist(ts, io_u_dist);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	log_info("  IO depths    : 1=%3.1f%%, 2=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%, 32=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3], io_u_dist[4], io_u_dist[5], io_u_dist[6]);
	log_info("     issued r/w: total=%lu/%lu, short=%lu/%lu\n", ts->total_io_u[0], ts->total_io_u[1], ts->short_io_u[0], ts->short_io_u[1]);

	show_latencies(io_u_lat_u, io_u_lat_m);
}

static void show_ddir_status_terse(struct thread_stat *ts,
				   struct group_run_stats *rs, int ddir)
{
	unsigned long min, max;
	unsigned long long bw;
	double mean, dev;

	bw = 0;
	if (ts->runtime[ddir])
		bw = ts->io_bytes[ddir] / ts->runtime[ddir];

	log_info(";%llu;%llu;%lu", ts->io_bytes[ddir] >> 10, bw, ts->runtime[ddir]);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		log_info(";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_info(";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
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


static void show_thread_status_terse(struct thread_stat *ts,
				     struct group_run_stats *rs)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;

	log_info("%s;%d;%d", ts->name, ts->groupid, ts->error);

	show_ddir_status_terse(ts, rs, 0);
	show_ddir_status_terse(ts, rs, 1);

	if (ts->total_run_time) {
		double runt = (double) ts->total_run_time;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	log_info(";%f%%;%f%%;%lu", usr_cpu, sys_cpu, ts->ctx);

	stat_calc_dist(ts, io_u_dist);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	log_info(";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%", io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3], io_u_dist[4], io_u_dist[5], io_u_dist[6]);

	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++)
		log_info(";%3.2f%%", io_u_lat_u[i]);
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++)
		log_info(";%3.2f%%", io_u_lat_m[i]);
	log_info("\n");

	if (ts->description)
		log_info(";%s", ts->description);

	log_info("\n");
}

static void sum_stat(struct io_stat *dst, struct io_stat *src, int nr)
{
	double mean, S;

	dst->min_val = min(dst->min_val, src->min_val);
	dst->max_val = max(dst->max_val, src->max_val);
	dst->samples += src->samples;

	/*
	 * Needs a new method for calculating stddev, we cannot just
	 * average them we do below for nr > 1
	 */
	if (nr == 1) {
		mean = src->mean;
		S = src->S;
	} else {
		mean = ((src->mean * (double) (nr - 1)) + dst->mean) / ((double) nr);
		S = ((src->S * (double) (nr - 1)) + dst->S) / ((double) nr);
	}

	dst->mean = mean;
	dst->S = S;
}

void show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	struct thread_stat *threadstats, *ts;
	int i, j, k, l, nr_ts, last_ts, idx;

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
		}

		if (td->error && !ts->error) {
			ts->error = td->error;
			ts->verror = td->verror;
		}

		for (l = 0; l <= DDIR_WRITE; l++) {
			sum_stat(&ts->clat_stat[l], &td->ts.clat_stat[l], idx);
			sum_stat(&ts->slat_stat[l], &td->ts.slat_stat[l], idx);
			sum_stat(&ts->bw_stat[l], &td->ts.bw_stat[l], idx);

			ts->stat_io_bytes[l] += td->ts.stat_io_bytes[l];
			ts->io_bytes[l] += td->ts.io_bytes[l];

			if (ts->runtime[l] < td->ts.runtime[l])
				ts->runtime[l] = td->ts.runtime[l];
		}

		ts->usr_time += td->ts.usr_time;
		ts->sys_time += td->ts.sys_time;
		ts->ctx += td->ts.ctx;

		for (k = 0; k < FIO_IO_U_MAP_NR; k++)
			ts->io_u_map[k] += td->ts.io_u_map[k];
		for (k = 0; k < FIO_IO_U_LAT_U_NR; k++)
			ts->io_u_lat_u[k] += td->ts.io_u_lat_u[k];
		for (k = 0; k < FIO_IO_U_LAT_M_NR; k++)
			ts->io_u_lat_m[k] += td->ts.io_u_lat_m[k];


		for (k = 0; k <= DDIR_WRITE; k++) {
			ts->total_io_u[k] += td->ts.total_io_u[k];
			ts->short_io_u[k] += td->ts.short_io_u[k];
		}

		ts->total_run_time += td->ts.total_run_time;
	}

	for (i = 0; i < nr_ts; i++) {
		unsigned long long bw;

		ts = &threadstats[i];
		rs = &runstats[ts->groupid];

		for (j = 0; j <= DDIR_WRITE; j++) {
			if (!ts->runtime[j])
				continue;
			if (ts->runtime[j] < rs->min_run[j] || !rs->min_run[j])
				rs->min_run[j] = ts->runtime[j];
			if (ts->runtime[j] > rs->max_run[j])
				rs->max_run[j] = ts->runtime[j];

			bw = 0;
			if (ts->runtime[j])
				bw = ts->io_bytes[j] / (unsigned long long) ts->runtime[j];
			if (bw < rs->min_bw[j])
				rs->min_bw[j] = bw;
			if (bw > rs->max_bw[j])
				rs->max_bw[j] = bw;

			rs->io_kb[j] += ts->io_bytes[j] >> 10;
		}
	}

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		if (rs->max_run[0])
			rs->agg[0] = (rs->io_kb[0]*1024) / rs->max_run[0];
		if (rs->max_run[1])
			rs->agg[1] = (rs->io_kb[1]*1024) / rs->max_run[1];
	}

	/*
	 * don't overwrite last signal output
	 */
	if (!terse_output)
		printf("\n");

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
			     enum fio_ddir ddir, unsigned long time)
{
	if (iolog->nr_samples == iolog->max_samples) {
		int new_size = sizeof(struct io_sample) * iolog->max_samples*2;

		iolog->log = realloc(iolog->log, new_size);
		iolog->max_samples <<= 1;
	}

	iolog->log[iolog->nr_samples].val = val;
	iolog->log[iolog->nr_samples].time = time;
	iolog->log[iolog->nr_samples].ddir = ddir;
	iolog->nr_samples++;
}

static void add_log_sample(struct thread_data *td, struct io_log *iolog,
			   unsigned long val, enum fio_ddir ddir)
{
	__add_log_sample(iolog, val, ddir, mtime_since_now(&td->epoch));
}

void add_agg_sample(unsigned long val, enum fio_ddir ddir)
{
	struct io_log *iolog = agg_io_log[ddir];

	__add_log_sample(iolog, val, ddir, mtime_since_genesis());
}

void add_clat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec)
{
	struct thread_stat *ts = &td->ts;

	add_stat_sample(&ts->clat_stat[ddir], usec);

	if (ts->clat_log)
		add_log_sample(td, ts->clat_log, usec, ddir);
}

void add_slat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec)
{
	struct thread_stat *ts = &td->ts;

	add_stat_sample(&ts->slat_stat[ddir], usec);

	if (ts->slat_log)
		add_log_sample(td, ts->slat_log, usec, ddir);
}

void add_bw_sample(struct thread_data *td, enum fio_ddir ddir,
		   struct timeval *t)
{
	struct thread_stat *ts = &td->ts;
	unsigned long spent = mtime_since(&ts->stat_sample_time[ddir], t);
	unsigned long rate;

	if (spent < td->o.bw_avg_time)
		return;

	rate = (td->this_io_bytes[ddir] - ts->stat_io_bytes[ddir]) / spent;
	add_stat_sample(&ts->bw_stat[ddir], rate);

	if (ts->bw_log)
		add_log_sample(td, ts->bw_log, rate, ddir);

	fio_gettime(&ts->stat_sample_time[ddir], NULL);
	ts->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
}
