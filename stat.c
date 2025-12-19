#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <math.h>

#include "fio.h"
#include "diskutil.h"
#include "lib/ieee754.h"
#include "json.h"
#include "lib/getrusage.h"
#include "idletime.h"
#include "lib/pow2.h"
#include "lib/output_buffer.h"
#include "helper_thread.h"
#include "smalloc.h"
#include "zbd.h"
#include "oslib/asprintf.h"

#ifdef WIN32
#define LOG_MSEC_SLACK	2
#else
#define LOG_MSEC_SLACK	1
#endif

struct log_sample {
	union io_sample_data data;
	uint32_t ddir;
	uint64_t bs;
	uint64_t offset;
	uint16_t priority;
	uint64_t issue_time;
};

struct fio_sem *stat_sem;

void clear_rusage_stat(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;

	fio_getrusage(&td->ru_start);
	ts->usr_time = ts->sys_time = 0;
	ts->ctx = 0;
	ts->minf = ts->majf = 0;
}

void update_rusage_stat(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;

	fio_getrusage(&td->ru_end);
	ts->usr_time += mtime_since_tv(&td->ru_start.ru_utime,
					&td->ru_end.ru_utime);
	ts->sys_time += mtime_since_tv(&td->ru_start.ru_stime,
					&td->ru_end.ru_stime);
	ts->ctx += td->ru_end.ru_nvcsw + td->ru_end.ru_nivcsw
			- (td->ru_start.ru_nvcsw + td->ru_start.ru_nivcsw);
	ts->minf += td->ru_end.ru_minflt - td->ru_start.ru_minflt;
	ts->majf += td->ru_end.ru_majflt - td->ru_start.ru_majflt;

	memcpy(&td->ru_start, &td->ru_end, sizeof(td->ru_end));
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
static unsigned int plat_val_to_idx(unsigned long long val)
{
	unsigned int msb, error_bits, base, offset, idx;

	/* Find MSB starting from bit 0 */
	if (val == 0)
		msb = 0;
	else
		msb = (sizeof(val)*8) - __builtin_clzll(val) - 1;

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
	idx = (base + offset) < (FIO_IO_U_PLAT_NR - 1) ?
		(base + offset) : (FIO_IO_U_PLAT_NR - 1);

	return idx;
}

/*
 * Convert the given index of the bucket array to the value
 * represented by the bucket
 */
static unsigned long long plat_idx_to_val(unsigned int idx)
{
	unsigned int error_bits;
	unsigned long long k, base;

	assert(idx < FIO_IO_U_PLAT_NR);

	/* MSB <= (FIO_IO_U_PLAT_BITS-1), cannot be rounded off. Use
	 * all bits of the sample as index */
	if (idx < (FIO_IO_U_PLAT_VAL << 1))
		return idx;

	/* Find the group and compute the minimum value of that group */
	error_bits = (idx >> FIO_IO_U_PLAT_BITS) - 1;
	base = ((unsigned long long) 1) << (error_bits + FIO_IO_U_PLAT_BITS);

	/* Find its bucket number of the group */
	k = idx % FIO_IO_U_PLAT_VAL;

	/* Return the mean of the range of the bucket */
	return base + ((k + 0.5) * (1 << error_bits));
}

static int double_cmp(const void *a, const void *b)
{
	const fio_fp64_t fa = *(const fio_fp64_t *) a;
	const fio_fp64_t fb = *(const fio_fp64_t *) b;
	int cmp = 0;

	if (fa.u.f > fb.u.f)
		cmp = 1;
	else if (fa.u.f < fb.u.f)
		cmp = -1;

	return cmp;
}

unsigned int calc_clat_percentiles(const uint64_t *io_u_plat, unsigned long long nr,
				   fio_fp64_t *plist, unsigned long long **output,
				   unsigned long long *maxv, unsigned long long *minv)
{
	unsigned long long sum = 0;
	unsigned int len, i, j = 0;
	unsigned long long *ovals = NULL;
	bool is_last;

	*minv = -1ULL;
	*maxv = 0;

	len = 0;
	while (len < FIO_IO_U_LIST_MAX_LEN && plist[len].u.f != 0.0)
		len++;

	if (!len)
		return 0;

	/*
	 * Sort the percentile list. Note that it may already be sorted if
	 * we are using the default values, but since it's a short list this
	 * isn't a worry. Also note that this does not work for NaN values.
	 */
	if (len > 1)
		qsort(plist, len, sizeof(plist[0]), double_cmp);

	ovals = malloc(len * sizeof(*ovals));
	if (!ovals)
		return 0;

	/*
	 * Calculate bucket values, note down max and min values
	 */
	is_last = false;
	for (i = 0; i < FIO_IO_U_PLAT_NR && !is_last; i++) {
		sum += io_u_plat[i];
		while (sum >= ((long double) plist[j].u.f / 100.0 * nr)) {
			assert(plist[j].u.f <= 100.0);

			ovals[j] = plat_idx_to_val(i);
			if (ovals[j] < *minv)
				*minv = ovals[j];
			if (ovals[j] > *maxv)
				*maxv = ovals[j];

			is_last = (j == len - 1) != 0;
			if (is_last)
				break;

			j++;
		}
	}

	if (!is_last)
		log_err("fio: error calculating latency percentiles\n");

	*output = ovals;
	return len;
}

/*
 * Find and display the p-th percentile of clat
 */
static void show_clat_percentiles(const uint64_t *io_u_plat, unsigned long long nr,
				  fio_fp64_t *plist, unsigned int precision,
				  const char *pre, struct buf_output *out)
{
	unsigned int divisor, len, i, j = 0;
	unsigned long long minv, maxv;
	unsigned long long *ovals;
	int per_line, scale_down, time_width;
	bool is_last;
	char fmt[32];

	len = calc_clat_percentiles(io_u_plat, nr, plist, &ovals, &maxv, &minv);
	if (!len || !ovals)
		return;

	/*
	 * We default to nsecs, but if the value range is such that we
	 * should scale down to usecs or msecs, do that.
	 */
	if (minv > 2000000 && maxv > 99999999ULL) {
		scale_down = 2;
		divisor = 1000000;
		log_buf(out, "    %s percentiles (msec):\n     |", pre);
	} else if (minv > 2000 && maxv > 99999) {
		scale_down = 1;
		divisor = 1000;
		log_buf(out, "    %s percentiles (usec):\n     |", pre);
	} else {
		scale_down = 0;
		divisor = 1;
		log_buf(out, "    %s percentiles (nsec):\n     |", pre);
	}


	time_width = max(5, (int) (log10(maxv / divisor) + 1));
	snprintf(fmt, sizeof(fmt), " %%%u.%ufth=[%%%dllu]%%c", precision + 3,
			precision, time_width);
	/* fmt will be something like " %5.2fth=[%4llu]%c" */
	per_line = (80 - 7) / (precision + 10 + time_width);

	for (j = 0; j < len; j++) {
		/* for formatting */
		if (j != 0 && (j % per_line) == 0)
			log_buf(out, "     |");

		/* end of the list */
		is_last = (j == len - 1) != 0;

		for (i = 0; i < scale_down; i++)
			ovals[j] = (ovals[j] + 999) / 1000;

		log_buf(out, fmt, plist[j].u.f, ovals[j], is_last ? '\n' : ',');

		if (is_last)
			break;

		if ((j % per_line) == per_line - 1)	/* for formatting */
			log_buf(out, "\n");
	}

	free(ovals);
}

static int get_nr_prios_with_samples(struct thread_stat *ts, enum fio_ddir ddir)
{
	int i, nr_prios_with_samples = 0;

	for (i = 0; i < ts->nr_clat_prio[ddir]; i++) {
		if (ts->clat_prio[ddir][i].clat_stat.samples)
			nr_prios_with_samples++;
	}

	return nr_prios_with_samples;
}

bool calc_lat(const struct io_stat *is, unsigned long long *min,
	      unsigned long long *max, double *mean, double *dev)
{
	double n = (double) is->samples;

	if (n == 0)
		return false;

	*min = is->min_val;
	*max = is->max_val;
	*mean = is->mean.u.f;

	if (n > 1.0)
		*dev = sqrt(is->S.u.f / (n - 1.0));
	else
		*dev = 0;

	return true;
}

static void show_mixed_group_stats(const struct group_run_stats *rs, struct buf_output *out)
{
	char *io, *agg, *min, *max;
	char *ioalt, *aggalt, *minalt, *maxalt;
	uint64_t io_mix = 0, agg_mix = 0, min_mix = -1, max_mix = 0;
	uint64_t min_run = -1, max_run = 0;
	const int i2p = is_power_of_2(rs->kb_base);
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (!rs->max_run[i])
			continue;
		io_mix += rs->iobytes[i];
		agg_mix += rs->agg[i];
		min_mix = min_mix < rs->min_bw[i] ? min_mix : rs->min_bw[i];
		max_mix = max_mix > rs->max_bw[i] ? max_mix : rs->max_bw[i];
		min_run = min_run < rs->min_run[i] ? min_run : rs->min_run[i];
		max_run = max_run > rs->max_run[i] ? max_run : rs->max_run[i];
	}
	io = num2str(io_mix, rs->sig_figs, 1, i2p, N2S_BYTE);
	ioalt = num2str(io_mix, rs->sig_figs, 1, !i2p, N2S_BYTE);
	agg = num2str(agg_mix, rs->sig_figs, 1, i2p, rs->unit_base);
	aggalt = num2str(agg_mix, rs->sig_figs, 1, !i2p, rs->unit_base);
	min = num2str(min_mix, rs->sig_figs, 1, i2p, rs->unit_base);
	minalt = num2str(min_mix, rs->sig_figs, 1, !i2p, rs->unit_base);
	max = num2str(max_mix, rs->sig_figs, 1, i2p, rs->unit_base);
	maxalt = num2str(max_mix, rs->sig_figs, 1, !i2p, rs->unit_base);
	log_buf(out, "  MIXED: bw=%s (%s), %s-%s (%s-%s), io=%s (%s), run=%llu-%llumsec\n",
			agg, aggalt, min, max, minalt, maxalt, io, ioalt,
			(unsigned long long) min_run,
			(unsigned long long) max_run);
	free(io);
	free(agg);
	free(min);
	free(max);
	free(ioalt);
	free(aggalt);
	free(minalt);
	free(maxalt);
}

void show_group_stats(const struct group_run_stats *rs, struct buf_output *out)
{
	char *io, *agg, *min, *max;
	char *ioalt, *aggalt, *minalt, *maxalt;
	const char *str[] = { "   READ", "  WRITE" , "   TRIM"};
	int i;

	log_buf(out, "\nRun status group %d (all jobs):\n", rs->groupid);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		const int i2p = is_power_of_2(rs->kb_base);

		if (!rs->max_run[i])
			continue;

		io = num2str(rs->iobytes[i], rs->sig_figs, 1, i2p, N2S_BYTE);
		ioalt = num2str(rs->iobytes[i], rs->sig_figs, 1, !i2p, N2S_BYTE);
		agg = num2str(rs->agg[i], rs->sig_figs, 1, i2p, rs->unit_base);
		aggalt = num2str(rs->agg[i], rs->sig_figs, 1, !i2p, rs->unit_base);
		min = num2str(rs->min_bw[i], rs->sig_figs, 1, i2p, rs->unit_base);
		minalt = num2str(rs->min_bw[i], rs->sig_figs, 1, !i2p, rs->unit_base);
		max = num2str(rs->max_bw[i], rs->sig_figs, 1, i2p, rs->unit_base);
		maxalt = num2str(rs->max_bw[i], rs->sig_figs, 1, !i2p, rs->unit_base);
		log_buf(out, "%s: bw=%s (%s), %s-%s (%s-%s), io=%s (%s), run=%llu-%llumsec\n",
				(rs->unified_rw_rep == UNIFIED_MIXED) ? "  MIXED" : str[i],
				agg, aggalt, min, max, minalt, maxalt, io, ioalt,
				(unsigned long long) rs->min_run[i],
				(unsigned long long) rs->max_run[i]);

		free(io);
		free(agg);
		free(min);
		free(max);
		free(ioalt);
		free(aggalt);
		free(minalt);
		free(maxalt);
	}

	/* Need to aggregate statistics to show mixed values */
	if (rs->unified_rw_rep == UNIFIED_BOTH)
		show_mixed_group_stats(rs, out);
}

void stat_calc_dist(const uint64_t *map, unsigned long total, double *io_u_dist)
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

static void stat_calc_lat(const struct thread_stat *ts, double *dst,
			  const uint64_t *src, int nr)
{
	unsigned long total = ddir_rw_sum(ts->total_io_u);
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

/*
 * To keep the terse format unaltered, add all of the ns latency
 * buckets to the first us latency bucket
 */
static void stat_calc_lat_nu(const struct thread_stat *ts, double *io_u_lat_u)
{
	unsigned long ntotal = 0, total = ddir_rw_sum(ts->total_io_u);
	int i;

	stat_calc_lat(ts, io_u_lat_u, ts->io_u_lat_u, FIO_IO_U_LAT_U_NR);

	for (i = 0; i < FIO_IO_U_LAT_N_NR; i++)
		ntotal += ts->io_u_lat_n[i];

	io_u_lat_u[0] += 100.0 * (double) ntotal / (double) total;
}

void stat_calc_lat_n(const struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_n, FIO_IO_U_LAT_N_NR);
}

void stat_calc_lat_u(const struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_u, FIO_IO_U_LAT_U_NR);
}

void stat_calc_lat_m(const struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_m, FIO_IO_U_LAT_M_NR);
}

static void display_lat(const char *name, unsigned long long min,
			unsigned long long max, double mean, double dev,
			struct buf_output *out)
{
	const char *base = "(nsec)";
	char *minp, *maxp;

	if (nsec_to_msec(&min, &max, &mean, &dev))
		base = "(msec)";
	else if (nsec_to_usec(&min, &max, &mean, &dev))
		base = "(usec)";

	minp = num2str(min, 6, 1, 0, N2S_NONE);
	maxp = num2str(max, 6, 1, 0, N2S_NONE);

	log_buf(out, "    %s %s: min=%s, max=%s, avg=%5.02f,"
		 " stdev=%5.02f\n", name, base, minp, maxp, mean, dev);

	free(minp);
	free(maxp);
}

static struct thread_stat *gen_mixed_ddir_stats_from_ts(const struct thread_stat *ts)
{
	struct thread_stat *ts_lcl;

	/*
	 * Handle aggregation of Reads (ddir = 0), Writes (ddir = 1), and
	 * Trims (ddir = 2)
	 */
	ts_lcl = malloc(sizeof(struct thread_stat));
	if (!ts_lcl) {
		log_err("fio: failed to allocate local thread stat\n");
		return NULL;
	}

	init_thread_stat(ts_lcl);

	/* calculate mixed stats  */
	ts_lcl->unified_rw_rep = UNIFIED_MIXED;
	ts_lcl->lat_percentiles = ts->lat_percentiles;
	ts_lcl->clat_percentiles = ts->clat_percentiles;
	ts_lcl->slat_percentiles = ts->slat_percentiles;
	ts_lcl->percentile_precision = ts->percentile_precision;
	memcpy(ts_lcl->percentile_list, ts->percentile_list, sizeof(ts->percentile_list));
	ts_lcl->sig_figs = ts->sig_figs;

	sum_thread_stats(ts_lcl, ts);

	return ts_lcl;
}

static double convert_agg_kbytes_percent(const struct group_run_stats *rs,
					 enum fio_ddir ddir, int mean)
{
	double p_of_agg = 100.0;
	if (rs && rs->agg[ddir] > 1024) {
		p_of_agg = mean * 100.0 / (double) (rs->agg[ddir] / 1024.0);

		if (p_of_agg > 100.0)
			p_of_agg = 100.0;
	}
	return p_of_agg;
}

static void show_ddir_status(const struct group_run_stats *rs, struct thread_stat *ts,
			     enum fio_ddir ddir, struct buf_output *out)
{
	unsigned long runt;
	unsigned long long min, max, bw, iops;
	double mean, dev;
	char *io_p, *bw_p, *bw_p_alt, *iops_p, *post_st = NULL;
	int i2p, i;
	const char *clat_type = ts->lat_percentiles ? "lat" : "clat";

	if (ddir_sync(ddir)) {
		if (calc_lat(&ts->sync_stat, &min, &max, &mean, &dev)) {
			log_buf(out, "  %s:\n", "fsync/fdatasync/sync_file_range");
			display_lat(io_ddir_name(ddir), min, max, mean, dev, out);
			show_clat_percentiles(ts->io_u_sync_plat,
						ts->sync_stat.samples,
						ts->percentile_list,
						ts->percentile_precision,
						io_ddir_name(ddir), out);
		}
		return;
	}

	assert(ddir_rw(ddir));

	if (!ts->runtime[ddir])
		return;

	i2p = is_power_of_2(rs->kb_base);
	runt = ts->runtime[ddir];

	bw = (1000 * ts->io_bytes[ddir]) / runt;
	io_p = num2str(ts->io_bytes[ddir], ts->sig_figs, 1, i2p, N2S_BYTE);
	bw_p = num2str(bw, ts->sig_figs, 1, i2p, ts->unit_base);
	bw_p_alt = num2str(bw, ts->sig_figs, 1, !i2p, ts->unit_base);

	iops = (1000 * (uint64_t)ts->total_io_u[ddir]) / runt;
	iops_p = num2str(iops, ts->sig_figs, 1, 0, N2S_NONE);
	if (ts->count_zone_resets)
		post_st = zbd_write_status(ts);
	else if (ddir == DDIR_READ && ts->cachehit && ts->cachemiss) {
		uint64_t total;
		double hit;

		total = ts->cachehit + ts->cachemiss;
		hit = (double) ts->cachehit / (double) total;
		hit *= 100.0;
		if (asprintf(&post_st, "; Cachehit=%0.2f%%", hit) < 0)
			post_st = NULL;
	}

	log_buf(out, "  %s: IOPS=%s, BW=%s (%s)(%s/%llumsec)%s\n",
			(ts->unified_rw_rep == UNIFIED_MIXED) ? "mixed" : io_ddir_name(ddir),
			iops_p, bw_p, bw_p_alt, io_p,
			(unsigned long long) ts->runtime[ddir],
			post_st ? : "");

	free(post_st);
	free(io_p);
	free(bw_p);
	free(bw_p_alt);
	free(iops_p);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		display_lat("slat", min, max, mean, dev, out);
	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		display_lat("clat", min, max, mean, dev, out);
	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev))
		display_lat(" lat", min, max, mean, dev, out);

	/* Only print per prio stats if there are >= 2 prios with samples */
	if (get_nr_prios_with_samples(ts, ddir) >= 2) {
		for (i = 0; i < ts->nr_clat_prio[ddir]; i++) {
			char buf[64];

			if (!calc_lat(&ts->clat_prio[ddir][i].clat_stat, &min,
				      &max, &mean, &dev))
				continue;

			snprintf(buf, sizeof(buf),
				 "%s prio %u/%u/%u",
				 clat_type,
				 ioprio_class(ts->clat_prio[ddir][i].ioprio),
				 ioprio(ts->clat_prio[ddir][i].ioprio),
				 ioprio_hint(ts->clat_prio[ddir][i].ioprio));
			display_lat(buf, min, max, mean, dev, out);
		}
	}

	if (ts->slat_percentiles && ts->slat_stat[ddir].samples > 0)
		show_clat_percentiles(ts->io_u_plat[FIO_SLAT][ddir],
					ts->slat_stat[ddir].samples,
					ts->percentile_list,
					ts->percentile_precision, "slat", out);
	if (ts->clat_percentiles && ts->clat_stat[ddir].samples > 0)
		show_clat_percentiles(ts->io_u_plat[FIO_CLAT][ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list,
					ts->percentile_precision, "clat", out);
	if (ts->lat_percentiles && ts->lat_stat[ddir].samples > 0)
		show_clat_percentiles(ts->io_u_plat[FIO_LAT][ddir],
					ts->lat_stat[ddir].samples,
					ts->percentile_list,
					ts->percentile_precision, "lat", out);

	if (ts->clat_percentiles || ts->lat_percentiles) {
		char prio_name[64];
		uint64_t samples;

		if (ts->lat_percentiles)
			samples = ts->lat_stat[ddir].samples;
		else
			samples = ts->clat_stat[ddir].samples;

		/* Only print per prio stats if there are >= 2 prios with samples */
		if (get_nr_prios_with_samples(ts, ddir) >= 2) {
			for (i = 0; i < ts->nr_clat_prio[ddir]; i++) {
				uint64_t prio_samples =
					ts->clat_prio[ddir][i].clat_stat.samples;

				if (!prio_samples)
					continue;

				snprintf(prio_name, sizeof(prio_name),
					 "%s prio %u/%u/%u (%.2f%% of IOs)",
					 clat_type,
					 ioprio_class(ts->clat_prio[ddir][i].ioprio),
					 ioprio(ts->clat_prio[ddir][i].ioprio),
					 ioprio_hint(ts->clat_prio[ddir][i].ioprio),
					 100. * (double) prio_samples / (double) samples);
				show_clat_percentiles(ts->clat_prio[ddir][i].io_u_plat,
						prio_samples, ts->percentile_list,
						ts->percentile_precision,
						prio_name, out);
			}
		}
	}

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg = 100.0, fkb_base = (double)rs->kb_base;
		const char *bw_str;

		if ((rs->unit_base == 1) && i2p)
			bw_str = "Kibit";
		else if (rs->unit_base == 1)
			bw_str = "kbit";
		else if (i2p)
			bw_str = "KiB";
		else
			bw_str = "kB";

		p_of_agg = convert_agg_kbytes_percent(rs, ddir, mean);

		if (rs->unit_base == 1) {
			min *= 8.0;
			max *= 8.0;
			mean *= 8.0;
			dev *= 8.0;
		}

		if (mean > fkb_base * fkb_base) {
			min /= fkb_base;
			max /= fkb_base;
			mean /= fkb_base;
			dev /= fkb_base;
			bw_str = (rs->unit_base == 1 ? "Mibit" : "MiB");
		}

		log_buf(out, "   bw (%5s/s): min=%5llu, max=%5llu, per=%3.2f%%, "
			"avg=%5.02f, stdev=%5.02f, samples=%" PRIu64 "\n",
			bw_str, min, max, p_of_agg, mean, dev,
			(&ts->bw_stat[ddir])->samples);
	}
	if (calc_lat(&ts->iops_stat[ddir], &min, &max, &mean, &dev)) {
		log_buf(out, "   iops        : min=%5llu, max=%5llu, "
			"avg=%5.02f, stdev=%5.02f, samples=%" PRIu64 "\n",
			min, max, mean, dev, (&ts->iops_stat[ddir])->samples);
	}
}

static void show_mixed_ddir_status(const struct group_run_stats *rs,
				   const struct thread_stat *ts,
				   struct buf_output *out)
{
	struct thread_stat *ts_lcl = gen_mixed_ddir_stats_from_ts(ts);

	if (ts_lcl)
		show_ddir_status(rs, ts_lcl, DDIR_READ, out);

	free_clat_prio_stats(ts_lcl);
	free(ts_lcl);
}

static bool show_lat(const double *io_u_lat, int nr, const char **ranges,
		     const char *msg, struct buf_output *out)
{
	bool new_line = true, shown = false;
	int i, line = 0;

	for (i = 0; i < nr; i++) {
		if (io_u_lat[i] <= 0.0)
			continue;
		shown = true;
		if (new_line) {
			if (line)
				log_buf(out, "\n");
			log_buf(out, "  lat (%s)   : ", msg);
			new_line = false;
			line = 0;
		}
		if (line)
			log_buf(out, ", ");
		log_buf(out, "%s%3.2f%%", ranges[i], io_u_lat[i]);
		line++;
		if (line == 5)
			new_line = true;
	}

	if (shown)
		log_buf(out, "\n");

	return true;
}

static void show_lat_n(const double *io_u_lat_n, struct buf_output *out)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", };

	show_lat(io_u_lat_n, FIO_IO_U_LAT_N_NR, ranges, "nsec", out);
}

static void show_lat_u(const double *io_u_lat_u, struct buf_output *out)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", };

	show_lat(io_u_lat_u, FIO_IO_U_LAT_U_NR, ranges, "usec", out);
}

static void show_lat_m(const double *io_u_lat_m, struct buf_output *out)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", "2000=",
				 ">=2000=", };

	show_lat(io_u_lat_m, FIO_IO_U_LAT_M_NR, ranges, "msec", out);
}

static void show_latencies(const struct thread_stat *ts, struct buf_output *out)
{
	double io_u_lat_n[FIO_IO_U_LAT_N_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];

	stat_calc_lat_n(ts, io_u_lat_n);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	show_lat_n(io_u_lat_n, out);
	show_lat_u(io_u_lat_u, out);
	show_lat_m(io_u_lat_m, out);
}

static int block_state_category(int block_state)
{
	switch (block_state) {
	case BLOCK_STATE_UNINIT:
		return 0;
	case BLOCK_STATE_TRIMMED:
	case BLOCK_STATE_WRITTEN:
		return 1;
	case BLOCK_STATE_WRITE_FAILURE:
	case BLOCK_STATE_TRIM_FAILURE:
		return 2;
	default:
		/* Silence compile warning on some BSDs and have a return */
		assert(0);
		return -1;
	}
}

static int compare_block_infos(const void *bs1, const void *bs2)
{
	uint64_t block1 = *(uint64_t *)bs1;
	uint64_t block2 = *(uint64_t *)bs2;
	int state1 = BLOCK_INFO_STATE(block1);
	int state2 = BLOCK_INFO_STATE(block2);
	int bscat1 = block_state_category(state1);
	int bscat2 = block_state_category(state2);
	int cycles1 = BLOCK_INFO_TRIMS(block1);
	int cycles2 = BLOCK_INFO_TRIMS(block2);

	if (bscat1 < bscat2)
		return -1;
	if (bscat1 > bscat2)
		return 1;

	if (cycles1 < cycles2)
		return -1;
	if (cycles1 > cycles2)
		return 1;

	if (state1 < state2)
		return -1;
	if (state1 > state2)
		return 1;

	assert(block1 == block2);
	return 0;
}

static int calc_block_percentiles(int nr_block_infos, uint32_t *block_infos,
				  fio_fp64_t *plist, unsigned int **percentiles,
				  unsigned int *types)
{
	int len = 0;
	int i, nr_uninit;

	qsort(block_infos, nr_block_infos, sizeof(uint32_t), compare_block_infos);

	while (len < FIO_IO_U_LIST_MAX_LEN && plist[len].u.f != 0.0)
		len++;

	if (!len)
		return 0;

	/*
	 * Sort the percentile list. Note that it may already be sorted if
	 * we are using the default values, but since it's a short list this
	 * isn't a worry. Also note that this does not work for NaN values.
	 */
	if (len > 1)
		qsort(plist, len, sizeof(plist[0]), double_cmp);

	/* Start only after the uninit entries end */
	for (nr_uninit = 0;
	     nr_uninit < nr_block_infos
		&& BLOCK_INFO_STATE(block_infos[nr_uninit]) == BLOCK_STATE_UNINIT;
	     nr_uninit ++)
		;

	if (nr_uninit == nr_block_infos)
		return 0;

	*percentiles = calloc(len, sizeof(**percentiles));

	for (i = 0; i < len; i++) {
		int idx = (plist[i].u.f * (nr_block_infos - nr_uninit) / 100)
				+ nr_uninit;
		(*percentiles)[i] = BLOCK_INFO_TRIMS(block_infos[idx]);
	}

	memset(types, 0, sizeof(*types) * BLOCK_STATE_COUNT);
	for (i = 0; i < nr_block_infos; i++)
		types[BLOCK_INFO_STATE(block_infos[i])]++;

	return len;
}

static const char *block_state_names[] = {
	[BLOCK_STATE_UNINIT] = "unwritten",
	[BLOCK_STATE_TRIMMED] = "trimmed",
	[BLOCK_STATE_WRITTEN] = "written",
	[BLOCK_STATE_TRIM_FAILURE] = "trim failure",
	[BLOCK_STATE_WRITE_FAILURE] = "write failure",
};

static void show_block_infos(int nr_block_infos, uint32_t *block_infos,
			     fio_fp64_t *plist, struct buf_output *out)
{
	int len, pos, i;
	unsigned int *percentiles = NULL;
	unsigned int block_state_counts[BLOCK_STATE_COUNT];

	len = calc_block_percentiles(nr_block_infos, block_infos, plist,
				     &percentiles, block_state_counts);

	log_buf(out, "  block lifetime percentiles :\n   |");
	pos = 0;
	for (i = 0; i < len; i++) {
		uint32_t block_info = percentiles[i];
#define LINE_LENGTH	75
		char str[LINE_LENGTH];
		int strln = snprintf(str, LINE_LENGTH, " %3.2fth=%u%c",
				     plist[i].u.f, block_info,
				     i == len - 1 ? '\n' : ',');
		assert(strln < LINE_LENGTH);
		if (pos + strln > LINE_LENGTH) {
			pos = 0;
			log_buf(out, "\n   |");
		}
		log_buf(out, "%s", str);
		pos += strln;
#undef LINE_LENGTH
	}
	if (percentiles)
		free(percentiles);

	log_buf(out, "        states               :");
	for (i = 0; i < BLOCK_STATE_COUNT; i++)
		log_buf(out, " %s=%u%c",
			 block_state_names[i], block_state_counts[i],
			 i == BLOCK_STATE_COUNT - 1 ? '\n' : ',');
}

static void show_ss_normal(const struct thread_stat *ts, struct buf_output *out)
{
	char *p1, *p1alt, *p2, *p3 = NULL;
	unsigned long long bw_mean, iops_mean, lat_mean;
	const int i2p = is_power_of_2(ts->kb_base);

	if (!ts->ss_dur)
		return;

	bw_mean = steadystate_bw_mean(ts);
	iops_mean = steadystate_iops_mean(ts);
	lat_mean = steadystate_lat_mean(ts);

	p1 = num2str(bw_mean / ts->kb_base, ts->sig_figs, ts->kb_base, i2p, ts->unit_base);
	p1alt = num2str(bw_mean / ts->kb_base, ts->sig_figs, ts->kb_base, !i2p, ts->unit_base);
	p2 = num2str(iops_mean, ts->sig_figs, 1, 0, N2S_NONE);
	if (ts->ss_state & FIO_SS_LAT) {
		const char *lat_unit = "nsec";
		unsigned long long lat_val = lat_mean;
		double lat_mean_d = lat_mean, lat_dev_d = 0.0;
		char *lat_num;

		if (nsec_to_msec(&lat_val, &lat_val, &lat_mean_d, &lat_dev_d))
			lat_unit = "msec";
		else if (nsec_to_usec(&lat_val, &lat_val, &lat_mean_d, &lat_dev_d))
			lat_unit = "usec";

		lat_num = num2str((unsigned long long)lat_mean_d, ts->sig_figs, 1, 0, N2S_NONE);
		if (asprintf(&p3, "%s%s", lat_num, lat_unit) < 0)
			p3 = NULL;
		free(lat_num);
	}

	log_buf(out, "  steadystate  : attained=%s, bw=%s (%s), iops=%s%s%s, %s%s=%.3f%s\n",
		ts->ss_state & FIO_SS_ATTAINED ? "yes" : "no",
		p1, p1alt, p2,
		p3 ? ", lat=" : "",
		p3 ? p3 : "",
		ts->ss_state & FIO_SS_IOPS ? "iops" : (ts->ss_state & FIO_SS_LAT ? "lat" : "bw"),
		ts->ss_state & FIO_SS_SLOPE ? " slope": " mean dev",
		ts->ss_criterion.u.f,
		ts->ss_state & FIO_SS_PCT ? "%" : "");

	free(p1);
	free(p1alt);
	free(p2);
	free(p3);
}

static void show_agg_stats(const struct disk_util_agg *agg, int terse,
			   struct buf_output *out)
{
	if (!agg->slavecount)
		return;

	if (!terse) {
		log_buf(out, ", aggrios=%llu/%llu, aggsectors=%llu/%llu, "
			 "aggrmerge=%llu/%llu, aggrticks=%llu/%llu, "
			 "aggrin_queue=%llu, aggrutil=%3.2f%%",
			(unsigned long long) agg->ios[0] / agg->slavecount,
			(unsigned long long) agg->ios[1] / agg->slavecount,
			(unsigned long long) agg->sectors[0] / agg->slavecount,
			(unsigned long long) agg->sectors[1] / agg->slavecount,
			(unsigned long long) agg->merges[0] / agg->slavecount,
			(unsigned long long) agg->merges[1] / agg->slavecount,
			(unsigned long long) agg->ticks[0] / agg->slavecount,
			(unsigned long long) agg->ticks[1] / agg->slavecount,
			(unsigned long long) agg->time_in_queue / agg->slavecount,
			agg->max_util.u.f);
	} else {
		log_buf(out, ";slaves;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%3.2f%%",
			(unsigned long long) agg->ios[0] / agg->slavecount,
			(unsigned long long) agg->ios[1] / agg->slavecount,
			(unsigned long long) agg->merges[0] / agg->slavecount,
			(unsigned long long) agg->merges[1] / agg->slavecount,
			(unsigned long long) agg->ticks[0] / agg->slavecount,
			(unsigned long long) agg->ticks[1] / agg->slavecount,
			(unsigned long long) agg->time_in_queue / agg->slavecount,
			agg->max_util.u.f);
	}
}

static void aggregate_slaves_stats(struct disk_util *masterdu)
{
	struct disk_util_agg *agg = &masterdu->agg;
	struct disk_util_stat *dus;
	struct flist_head *entry;
	struct disk_util *slavedu;
	double util;

	flist_for_each(entry, &masterdu->slaves) {
		slavedu = flist_entry(entry, struct disk_util, slavelist);
		dus = &slavedu->dus;
		agg->ios[0] += dus->s.ios[0];
		agg->ios[1] += dus->s.ios[1];
		agg->merges[0] += dus->s.merges[0];
		agg->merges[1] += dus->s.merges[1];
		agg->sectors[0] += dus->s.sectors[0];
		agg->sectors[1] += dus->s.sectors[1];
		agg->ticks[0] += dus->s.ticks[0];
		agg->ticks[1] += dus->s.ticks[1];
		agg->time_in_queue += dus->s.time_in_queue;
		agg->slavecount++;

		util = (double) (100 * dus->s.io_ticks / (double) slavedu->dus.s.msec);
		/* System utilization is the utilization of the
		 * component with the highest utilization.
		 */
		if (util > agg->max_util.u.f)
			agg->max_util.u.f = util;

	}

	if (agg->max_util.u.f > 100.0)
		agg->max_util.u.f = 100.0;
}

void print_disk_util(const struct disk_util_stat *dus, const struct disk_util_agg *agg,
		     int terse, struct buf_output *out)
{
	double util = 0;

	if (dus->s.msec)
		util = (double) 100 * dus->s.io_ticks / (double) dus->s.msec;
	if (util > 100.0)
		util = 100.0;

	if (!terse) {
		if (agg->slavecount)
			log_buf(out, "  ");

		log_buf(out, "  %s: ios=%llu/%llu, sectors=%llu/%llu, "
			"merge=%llu/%llu, ticks=%llu/%llu, in_queue=%llu, "
			"util=%3.2f%%",
				dus->name,
				(unsigned long long) dus->s.ios[0],
				(unsigned long long) dus->s.ios[1],
				(unsigned long long) dus->s.sectors[0],
				(unsigned long long) dus->s.sectors[1],
				(unsigned long long) dus->s.merges[0],
				(unsigned long long) dus->s.merges[1],
				(unsigned long long) dus->s.ticks[0],
				(unsigned long long) dus->s.ticks[1],
				(unsigned long long) dus->s.time_in_queue,
				util);
	} else {
		log_buf(out, ";%s;%llu;%llu;%llu;%llu;%llu;%llu;%llu;%3.2f%%",
				dus->name,
				(unsigned long long) dus->s.ios[0],
				(unsigned long long) dus->s.ios[1],
				(unsigned long long) dus->s.merges[0],
				(unsigned long long) dus->s.merges[1],
				(unsigned long long) dus->s.ticks[0],
				(unsigned long long) dus->s.ticks[1],
				(unsigned long long) dus->s.time_in_queue,
				util);
	}

	/*
	 * If the device has slaves, aggregate the stats for
	 * those slave devices also.
	 */
	show_agg_stats(agg, terse, out);

	if (!terse)
		log_buf(out, "\n");
}

void json_array_add_disk_util(const struct disk_util_stat *dus,
			      const struct disk_util_agg *agg, struct json_array *array)
{
	struct json_object *obj;
	double util = 0;

	if (dus->s.msec)
		util = (double) 100 * dus->s.io_ticks / (double) dus->s.msec;
	if (util > 100.0)
		util = 100.0;

	obj = json_create_object();
	json_array_add_value_object(array, obj);

	json_object_add_value_string(obj, "name", (const char *)dus->name);
	json_object_add_value_int(obj, "read_ios", dus->s.ios[0]);
	json_object_add_value_int(obj, "write_ios", dus->s.ios[1]);
	json_object_add_value_int(obj, "read_sectors", dus->s.sectors[0]);
	json_object_add_value_int(obj, "write_sectors", dus->s.sectors[1]);
	json_object_add_value_int(obj, "read_merges", dus->s.merges[0]);
	json_object_add_value_int(obj, "write_merges", dus->s.merges[1]);
	json_object_add_value_int(obj, "read_ticks", dus->s.ticks[0]);
	json_object_add_value_int(obj, "write_ticks", dus->s.ticks[1]);
	json_object_add_value_int(obj, "in_queue", dus->s.time_in_queue);
	json_object_add_value_float(obj, "util", util);

	/*
	 * If the device has slaves, aggregate the stats for
	 * those slave devices also.
	 */
	if (!agg->slavecount)
		return;
	json_object_add_value_int(obj, "aggr_read_ios",
				agg->ios[0] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_write_ios",
				agg->ios[1] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_read_sectors",
				agg->sectors[0] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_write_sectors",
				agg->sectors[1] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_read_merges",
				agg->merges[0] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_write_merge",
				agg->merges[1] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_read_ticks",
				agg->ticks[0] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_write_ticks",
				agg->ticks[1] / agg->slavecount);
	json_object_add_value_int(obj, "aggr_in_queue",
				agg->time_in_queue / agg->slavecount);
	json_object_add_value_float(obj, "aggr_util", agg->max_util.u.f);
}

static void json_object_add_disk_utils(struct json_object *obj,
				       struct flist_head *head)
{
	struct json_array *array = json_create_array();
	struct flist_head *entry;
	struct disk_util *du;

	json_object_add_value_array(obj, "disk_util", array);

	flist_for_each(entry, head) {
		du = flist_entry(entry, struct disk_util, list);

		aggregate_slaves_stats(du);
		json_array_add_disk_util(&du->dus, &du->agg, array);
	}
}

static void show_disk_util(int terse, struct json_object *parent,
			   struct buf_output *out)
{
	struct flist_head *entry;
	struct disk_util *du;
	bool do_json;

	if (!is_running_backend())
		return;

	if (flist_empty(&disk_list))
		return;

	if ((output_format & FIO_OUTPUT_JSON) && parent)
		do_json = true;
	else
		do_json = false;

	if (!terse && !do_json)
		log_buf(out, "\nDisk stats (read/write):\n");

	if (do_json) {
		json_object_add_disk_utils(parent, &disk_list);
	} else if (output_format & ~(FIO_OUTPUT_JSON | FIO_OUTPUT_JSON_PLUS)) {
		flist_for_each(entry, &disk_list) {
			du = flist_entry(entry, struct disk_util, list);

			aggregate_slaves_stats(du);
			print_disk_util(&du->dus, &du->agg, terse, out);
		}
	}
}

static void show_thread_status_normal(struct thread_stat *ts,
				      const struct group_run_stats *rs,
				      struct buf_output *out)
{
	double usr_cpu, sys_cpu;
	unsigned long runtime;
	double io_u_dist[FIO_IO_U_MAP_NR];
	time_t time_p;
	char time_buf[32];

	if (!ddir_rw_sum(ts->io_bytes) && !ddir_rw_sum(ts->total_io_u))
		return;

	memset(time_buf, 0, sizeof(time_buf));

	time(&time_p);
	os_ctime_r((const time_t *) &time_p, time_buf, sizeof(time_buf));

	if (!ts->error) {
		log_buf(out, "%s: (groupid=%d, jobs=%d): err=%2d: pid=%d: %s",
					ts->name, ts->groupid, ts->members,
					ts->error, (int) ts->pid, time_buf);
	} else {
		log_buf(out, "%s: (groupid=%d, jobs=%d): err=%2d (%s): pid=%d: %s",
					ts->name, ts->groupid, ts->members,
					ts->error, ts->verror, (int) ts->pid,
					time_buf);
	}

	if (strlen(ts->description))
		log_buf(out, "  Description  : [%s]\n", ts->description);

	for_each_rw_ddir(ddir) {
		if (ts->io_bytes[ddir])
			show_ddir_status(rs, ts, ddir, out);
	}

	if (ts->unified_rw_rep == UNIFIED_BOTH)
		show_mixed_ddir_status(rs, ts, out);

	show_latencies(ts, out);

	if (ts->sync_stat.samples)
		show_ddir_status(rs, ts, DDIR_SYNC, out);

	runtime = ts->total_run_time;
	if (runtime) {
		double runt = (double) runtime;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	log_buf(out, "  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%llu,"
		 " majf=%llu, minf=%llu\n", usr_cpu, sys_cpu,
			(unsigned long long) ts->ctx,
			(unsigned long long) ts->majf,
			(unsigned long long) ts->minf);

	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);
	log_buf(out, "  IO depths    : 1=%3.1f%%, 2=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%,"
		 " 16=%3.1f%%, 32=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);

	stat_calc_dist(ts->io_u_submit, ts->total_submit, io_u_dist);
	log_buf(out, "     submit    : 0=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%,"
		 " 32=%3.1f%%, 64=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);
	stat_calc_dist(ts->io_u_complete, ts->total_complete, io_u_dist);
	log_buf(out, "     complete  : 0=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%,"
		 " 32=%3.1f%%, 64=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0],
					io_u_dist[1], io_u_dist[2],
					io_u_dist[3], io_u_dist[4],
					io_u_dist[5], io_u_dist[6]);
	log_buf(out, "     issued rwts: total=%llu,%llu,%llu,%llu"
				 " short=%llu,%llu,%llu,0"
				 " dropped=%llu,%llu,%llu,0\n",
					(unsigned long long) ts->total_io_u[0],
					(unsigned long long) ts->total_io_u[1],
					(unsigned long long) ts->total_io_u[2],
					(unsigned long long) ts->total_io_u[3],
					(unsigned long long) ts->short_io_u[0],
					(unsigned long long) ts->short_io_u[1],
					(unsigned long long) ts->short_io_u[2],
					(unsigned long long) ts->drop_io_u[0],
					(unsigned long long) ts->drop_io_u[1],
					(unsigned long long) ts->drop_io_u[2]);
	if (ts->continue_on_error) {
		log_buf(out, "     errors    : total=%llu, first_error=%d/<%s>\n",
					(unsigned long long)ts->total_err_count,
					ts->first_error,
					strerror(ts->first_error));
	}
	if (ts->latency_depth) {
		log_buf(out, "     latency   : target=%llu, window=%llu, percentile=%.2f%%, depth=%u\n",
					(unsigned long long)ts->latency_target,
					(unsigned long long)ts->latency_window,
					ts->latency_percentile.u.f,
					ts->latency_depth);
	}

	if (ts->nr_block_infos)
		show_block_infos(ts->nr_block_infos, ts->block_infos,
				  ts->percentile_list, out);

	if (ts->ss_dur)
		show_ss_normal(ts, out);
}

static void show_ddir_status_terse(struct thread_stat *ts,
				   const struct group_run_stats *rs,
				   enum fio_ddir ddir, int ver,
				   struct buf_output *out)
{
	unsigned long long min, max, minv, maxv, bw, iops;
	unsigned long long *ovals = NULL;
	double mean, dev;
	unsigned int len;
	int i, bw_stat;

	assert(ddir_rw(ddir));

	iops = bw = 0;
	if (ts->runtime[ddir]) {
		uint64_t runt = ts->runtime[ddir];

		bw = ((1000 * ts->io_bytes[ddir]) / runt) / 1024; /* KiB/s */
		iops = (1000 * (uint64_t) ts->total_io_u[ddir]) / runt;
	}

	log_buf(out, ";%llu;%llu;%llu;%llu",
		(unsigned long long) ts->io_bytes[ddir] >> 10, bw, iops,
					(unsigned long long) ts->runtime[ddir]);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%llu;%llu;%f;%f", min/1000, max/1000, mean/1000, dev/1000);
	else
		log_buf(out, ";%llu;%llu;%f;%f", 0ULL, 0ULL, 0.0, 0.0);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%llu;%llu;%f;%f", min/1000, max/1000, mean/1000, dev/1000);
	else
		log_buf(out, ";%llu;%llu;%f;%f", 0ULL, 0ULL, 0.0, 0.0);

	if (ts->lat_percentiles) {
		len = calc_clat_percentiles(ts->io_u_plat[FIO_LAT][ddir],
					ts->lat_stat[ddir].samples,
					ts->percentile_list, &ovals, &maxv,
					&minv);
	} else if (ts->clat_percentiles) {
		len = calc_clat_percentiles(ts->io_u_plat[FIO_CLAT][ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list, &ovals, &maxv,
					&minv);
	} else {
		len = 0;
	}

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		if (i >= len) {
			log_buf(out, ";0%%=0");
			continue;
		}
		log_buf(out, ";%f%%=%llu", ts->percentile_list[i].u.f, ovals[i]/1000);
	}

	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%llu;%llu;%f;%f", min/1000, max/1000, mean/1000, dev/1000);
	else
		log_buf(out, ";%llu;%llu;%f;%f", 0ULL, 0ULL, 0.0, 0.0);

	free(ovals);

	bw_stat = calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev);
	if (bw_stat) {
		double p_of_agg = 100.0;

		if (rs->agg[ddir]) {
			p_of_agg = mean * 100 / (double) (rs->agg[ddir] / 1024);
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}

		log_buf(out, ";%llu;%llu;%f%%;%f;%f", min, max, p_of_agg, mean, dev);
	} else {
		log_buf(out, ";%llu;%llu;%f%%;%f;%f", 0ULL, 0ULL, 0.0, 0.0, 0.0);
	}

	if (ver == 5) {
		if (bw_stat)
			log_buf(out, ";%" PRIu64, (&ts->bw_stat[ddir])->samples);
		else
			log_buf(out, ";%lu", 0UL);

		if (calc_lat(&ts->iops_stat[ddir], &min, &max, &mean, &dev))
			log_buf(out, ";%llu;%llu;%f;%f;%" PRIu64, min, max,
				mean, dev, (&ts->iops_stat[ddir])->samples);
		else
			log_buf(out, ";%llu;%llu;%f;%f;%lu", 0ULL, 0ULL, 0.0, 0.0, 0UL);
	}
}

static void show_mixed_ddir_status_terse(const struct thread_stat *ts,
					 const struct group_run_stats *rs,
					 int ver, struct buf_output *out)
{
	struct thread_stat *ts_lcl = gen_mixed_ddir_stats_from_ts(ts);

	if (ts_lcl)
		show_ddir_status_terse(ts_lcl, rs, DDIR_READ, ver, out);

	free_clat_prio_stats(ts_lcl);
	free(ts_lcl);
}

static struct json_object *add_ddir_lat_json(struct thread_stat *ts,
					     uint32_t percentiles,
					     const struct io_stat *lat_stat,
					     const uint64_t *io_u_plat)
{
	char buf[120];
	double mean, dev;
	unsigned int i, len;
	struct json_object *lat_object, *percentile_object, *clat_bins_object;
	unsigned long long min, max, maxv, minv, *ovals = NULL;

	if (!calc_lat(lat_stat, &min, &max, &mean, &dev)) {
		min = max = 0;
		mean = dev = 0.0;
	}
	lat_object = json_create_object();
	json_object_add_value_int(lat_object, "min", min);
	json_object_add_value_int(lat_object, "max", max);
	json_object_add_value_float(lat_object, "mean", mean);
	json_object_add_value_float(lat_object, "stddev", dev);
	json_object_add_value_int(lat_object, "N", lat_stat->samples);

	if (percentiles && lat_stat->samples) {
		len = calc_clat_percentiles(io_u_plat, lat_stat->samples,
				ts->percentile_list, &ovals, &maxv, &minv);

		if (len > FIO_IO_U_LIST_MAX_LEN)
			len = FIO_IO_U_LIST_MAX_LEN;

		percentile_object = json_create_object();
		json_object_add_value_object(lat_object, "percentile", percentile_object);
		for (i = 0; i < len; i++) {
			snprintf(buf, sizeof(buf), "%f", ts->percentile_list[i].u.f);
			json_object_add_value_int(percentile_object, buf, ovals[i]);
		}
		free(ovals);

		if (output_format & FIO_OUTPUT_JSON_PLUS) {
			clat_bins_object = json_create_object();
			json_object_add_value_object(lat_object, "bins", clat_bins_object);

			for(i = 0; i < FIO_IO_U_PLAT_NR; i++)
				if (io_u_plat[i]) {
					snprintf(buf, sizeof(buf), "%llu", plat_idx_to_val(i));
					json_object_add_value_int(clat_bins_object, buf, io_u_plat[i]);
				}
		}
	}

	return lat_object;
}

static void add_ddir_status_json(struct thread_stat *ts,
				 const struct group_run_stats *rs, enum fio_ddir ddir,
				 struct json_object *parent)
{
	unsigned long long min, max;
	unsigned long long bw_bytes, bw;
	double mean, dev, iops;
	struct json_object *dir_object, *tmp_object;
	double p_of_agg = 100.0;

	assert(ddir_rw(ddir) || ddir_sync(ddir));

	if ((ts->unified_rw_rep == UNIFIED_MIXED) && ddir != DDIR_READ)
		return;

	dir_object = json_create_object();
	json_object_add_value_object(parent,
		(ts->unified_rw_rep == UNIFIED_MIXED) ? "mixed" : io_ddir_name(ddir), dir_object);

	if (ddir_rw(ddir)) {
		bw_bytes = 0;
		bw = 0;
		iops = 0.0;
		if (ts->runtime[ddir]) {
			uint64_t runt = ts->runtime[ddir];

			bw_bytes = ((1000 * ts->io_bytes[ddir]) / runt); /* Bytes/s */
			bw = bw_bytes / 1024; /* KiB/s */
			iops = (1000.0 * (uint64_t) ts->total_io_u[ddir]) / runt;
		}

		json_object_add_value_int(dir_object, "io_bytes", ts->io_bytes[ddir]);
		json_object_add_value_int(dir_object, "io_kbytes", ts->io_bytes[ddir] >> 10);
		json_object_add_value_int(dir_object, "bw_bytes", bw_bytes);
		json_object_add_value_int(dir_object, "bw", bw);
		json_object_add_value_float(dir_object, "iops", iops);
		json_object_add_value_int(dir_object, "runtime", ts->runtime[ddir]);
		json_object_add_value_int(dir_object, "total_ios", ts->total_io_u[ddir]);
		json_object_add_value_int(dir_object, "short_ios", ts->short_io_u[ddir]);
		json_object_add_value_int(dir_object, "drop_ios", ts->drop_io_u[ddir]);

		tmp_object = add_ddir_lat_json(ts, ts->slat_percentiles,
				&ts->slat_stat[ddir], ts->io_u_plat[FIO_SLAT][ddir]);
		json_object_add_value_object(dir_object, "slat_ns", tmp_object);

		tmp_object = add_ddir_lat_json(ts, ts->clat_percentiles,
				&ts->clat_stat[ddir], ts->io_u_plat[FIO_CLAT][ddir]);
		json_object_add_value_object(dir_object, "clat_ns", tmp_object);

		tmp_object = add_ddir_lat_json(ts, ts->lat_percentiles,
				&ts->lat_stat[ddir], ts->io_u_plat[FIO_LAT][ddir]);
		json_object_add_value_object(dir_object, "lat_ns", tmp_object);
	} else {
		json_object_add_value_int(dir_object, "total_ios", ts->total_io_u[DDIR_SYNC]);
		tmp_object = add_ddir_lat_json(ts, ts->lat_percentiles | ts->clat_percentiles,
				&ts->sync_stat, ts->io_u_sync_plat);
		json_object_add_value_object(dir_object, "lat_ns", tmp_object);
	}

	if (!ddir_rw(ddir))
		return;

	/* Only include per prio stats if there are >= 2 prios with samples */
	if (get_nr_prios_with_samples(ts, ddir) >= 2) {
		struct json_array *array = json_create_array();
		const char *obj_name;
		int i;

		if (ts->lat_percentiles)
			obj_name = "lat_ns";
		else
			obj_name = "clat_ns";

		json_object_add_value_array(dir_object, "prios", array);

		for (i = 0; i < ts->nr_clat_prio[ddir]; i++) {
			struct json_object *obj;

			if (!ts->clat_prio[ddir][i].clat_stat.samples)
				continue;

			obj = json_create_object();

			json_object_add_value_int(obj, "prioclass",
				ioprio_class(ts->clat_prio[ddir][i].ioprio));
			json_object_add_value_int(obj, "prio",
				ioprio(ts->clat_prio[ddir][i].ioprio));
			json_object_add_value_int(obj, "priohint",
				ioprio_hint(ts->clat_prio[ddir][i].ioprio));

			tmp_object = add_ddir_lat_json(ts,
					ts->clat_percentiles | ts->lat_percentiles,
					&ts->clat_prio[ddir][i].clat_stat,
					ts->clat_prio[ddir][i].io_u_plat);
			json_object_add_value_object(obj, obj_name, tmp_object);
			json_array_add_value_object(array, obj);
		}
	}

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		p_of_agg = convert_agg_kbytes_percent(rs, ddir, mean);
	} else {
		min = max = 0;
		p_of_agg = mean = dev = 0.0;
	}

	json_object_add_value_int(dir_object, "bw_min", min);
	json_object_add_value_int(dir_object, "bw_max", max);
	json_object_add_value_float(dir_object, "bw_agg", p_of_agg);
	json_object_add_value_float(dir_object, "bw_mean", mean);
	json_object_add_value_float(dir_object, "bw_dev", dev);
	json_object_add_value_int(dir_object, "bw_samples",
				(&ts->bw_stat[ddir])->samples);

	if (!calc_lat(&ts->iops_stat[ddir], &min, &max, &mean, &dev)) {
		min = max = 0;
		mean = dev = 0.0;
	}
	json_object_add_value_int(dir_object, "iops_min", min);
	json_object_add_value_int(dir_object, "iops_max", max);
	json_object_add_value_float(dir_object, "iops_mean", mean);
	json_object_add_value_float(dir_object, "iops_stddev", dev);
	json_object_add_value_int(dir_object, "iops_samples",
				(&ts->iops_stat[ddir])->samples);

	if (ts->cachehit + ts->cachemiss) {
		uint64_t total;
		double hit;

		total = ts->cachehit + ts->cachemiss;
		hit = (double) ts->cachehit / (double) total;
		hit *= 100.0;
		json_object_add_value_float(dir_object, "cachehit", hit);
	}
}

static void add_mixed_ddir_status_json(struct thread_stat *ts,
		struct group_run_stats *rs, struct json_object *parent)
{
	struct thread_stat *ts_lcl = gen_mixed_ddir_stats_from_ts(ts);

	/* add the aggregated stats to json parent */
	if (ts_lcl)
		add_ddir_status_json(ts_lcl, rs, DDIR_READ, parent);

	free_clat_prio_stats(ts_lcl);
	free(ts_lcl);
}

static void show_thread_status_terse_all(struct thread_stat *ts,
					 struct group_run_stats *rs, int ver,
					 struct buf_output *out)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;

	/* General Info */
	if (ver == 2)
		log_buf(out, "2;%s;%d;%d", ts->name, ts->groupid, ts->error);
	else
		log_buf(out, "%d;%s;%s;%d;%d", ver, fio_version_string,
			ts->name, ts->groupid, ts->error);

	/* Log Read Status, or mixed if unified_rw_rep = 1 */
	show_ddir_status_terse(ts, rs, DDIR_READ, ver, out);
	if (ts->unified_rw_rep != UNIFIED_MIXED) {
		/* Log Write Status */
		show_ddir_status_terse(ts, rs, DDIR_WRITE, ver, out);
		/* Log Trim Status */
		if (ver == 2 || ver == 4 || ver == 5)
			show_ddir_status_terse(ts, rs, DDIR_TRIM, ver, out);
	}
	if (ts->unified_rw_rep == UNIFIED_BOTH)
		show_mixed_ddir_status_terse(ts, rs, ver, out);
	/* CPU Usage */
	if (ts->total_run_time) {
		double runt = (double) ts->total_run_time;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	log_buf(out, ";%f%%;%f%%;%llu;%llu;%llu", usr_cpu, sys_cpu,
						(unsigned long long) ts->ctx,
						(unsigned long long) ts->majf,
						(unsigned long long) ts->minf);

	/* Calc % distribution of IO depths, usecond, msecond latency */
	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);
	stat_calc_lat_nu(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	/* Only show fixed 7 I/O depth levels*/
	log_buf(out, ";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%",
			io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3],
			io_u_dist[4], io_u_dist[5], io_u_dist[6]);

	/* Microsecond latency */
	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++)
		log_buf(out, ";%3.2f%%", io_u_lat_u[i]);
	/* Millisecond latency */
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++)
		log_buf(out, ";%3.2f%%", io_u_lat_m[i]);

	/* disk util stats, if any */
	if (ver >= 3 && is_running_backend())
		show_disk_util(1, NULL, out);

	/* Additional output if continue_on_error set - default off*/
	if (ts->continue_on_error)
		log_buf(out, ";%llu;%d", (unsigned long long) ts->total_err_count, ts->first_error);

	/* Additional output if description is set */
	if (strlen(ts->description)) {
		if (ver == 2)
			log_buf(out, "\n");
		log_buf(out, ";%s", ts->description);
	}

	log_buf(out, "\n");
}

static void json_add_job_opts(struct json_object *root, const char *name,
			      struct flist_head *opt_list)
{
	struct json_object *dir_object;
	struct flist_head *entry;
	struct print_option *p;

	if (flist_empty(opt_list))
		return;

	dir_object = json_create_object();
	json_object_add_value_object(root, name, dir_object);

	flist_for_each(entry, opt_list) {
		p = flist_entry(entry, struct print_option, list);
		json_object_add_value_string(dir_object, p->name, p->value);
	}
}

static struct json_object *show_thread_status_json(struct thread_stat *ts,
						   struct group_run_stats *rs,
						   struct flist_head *opt_list)
{
	struct json_object *root, *tmp;
	struct jobs_eta *je;
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_n[FIO_IO_U_LAT_N_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;
	size_t size;

	root = json_create_object();
	json_object_add_value_string(root, "jobname", ts->name);
	json_object_add_value_int(root, "groupid", ts->groupid);
	json_object_add_value_int(root, "job_start", ts->job_start);
	json_object_add_value_int(root, "error", ts->error);

	/* ETA Info */
	je = get_jobs_eta(true, &size);
	if (je) {
		json_object_add_value_int(root, "eta", je->eta_sec);
		json_object_add_value_int(root, "elapsed", je->elapsed_sec);
		free(je);
	}

	if (opt_list)
		json_add_job_opts(root, "job options", opt_list);

	add_ddir_status_json(ts, rs, DDIR_READ, root);
	add_ddir_status_json(ts, rs, DDIR_WRITE, root);
	add_ddir_status_json(ts, rs, DDIR_TRIM, root);
	add_ddir_status_json(ts, rs, DDIR_SYNC, root);

	if (ts->unified_rw_rep == UNIFIED_BOTH)
		add_mixed_ddir_status_json(ts, rs, root);

	/* CPU Usage */
	if (ts->total_run_time) {
		double runt = (double) ts->total_run_time;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}
	json_object_add_value_int(root, "job_runtime", ts->total_run_time);
	json_object_add_value_float(root, "usr_cpu", usr_cpu);
	json_object_add_value_float(root, "sys_cpu", sys_cpu);
	json_object_add_value_int(root, "ctx", ts->ctx);
	json_object_add_value_int(root, "majf", ts->majf);
	json_object_add_value_int(root, "minf", ts->minf);

	/* Calc % distribution of IO depths */
	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);
	tmp = json_create_object();
	json_object_add_value_object(root, "iodepth_level", tmp);
	/* Only show fixed 7 I/O depth levels*/
	for (i = 0; i < 7; i++) {
		char name[20];
		if (i < 6)
			snprintf(name, 20, "%d", 1 << i);
		else
			snprintf(name, 20, ">=%d", 1 << i);
		json_object_add_value_float(tmp, (const char *)name, io_u_dist[i]);
	}

	/* Calc % distribution of submit IO depths */
	stat_calc_dist(ts->io_u_submit, ts->total_submit, io_u_dist);
	tmp = json_create_object();
	json_object_add_value_object(root, "iodepth_submit", tmp);
	/* Only show fixed 7 I/O depth levels*/
	for (i = 0; i < 7; i++) {
		char name[20];
		if (i == 0)
			snprintf(name, 20, "0");
		else if (i < 6)
			snprintf(name, 20, "%d", 1 << (i+1));
		else
			snprintf(name, 20, ">=%d", 1 << i);
		json_object_add_value_float(tmp, (const char *)name, io_u_dist[i]);
	}

	/* Calc % distribution of completion IO depths */
	stat_calc_dist(ts->io_u_complete, ts->total_complete, io_u_dist);
	tmp = json_create_object();
	json_object_add_value_object(root, "iodepth_complete", tmp);
	/* Only show fixed 7 I/O depth levels*/
	for (i = 0; i < 7; i++) {
		char name[20];
		if (i == 0)
			snprintf(name, 20, "0");
		else if (i < 6)
			snprintf(name, 20, "%d", 1 << (i+1));
		else
			snprintf(name, 20, ">=%d", 1 << i);
		json_object_add_value_float(tmp, (const char *)name, io_u_dist[i]);
	}

	/* Calc % distribution of nsecond, usecond, msecond latency */
	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);
	stat_calc_lat_n(ts, io_u_lat_n);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	/* Nanosecond latency */
	tmp = json_create_object();
	json_object_add_value_object(root, "latency_ns", tmp);
	for (i = 0; i < FIO_IO_U_LAT_N_NR; i++) {
		const char *ranges[] = { "2", "4", "10", "20", "50", "100",
				 "250", "500", "750", "1000", };
		json_object_add_value_float(tmp, ranges[i], io_u_lat_n[i]);
	}
	/* Microsecond latency */
	tmp = json_create_object();
	json_object_add_value_object(root, "latency_us", tmp);
	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++) {
		const char *ranges[] = { "2", "4", "10", "20", "50", "100",
				 "250", "500", "750", "1000", };
		json_object_add_value_float(tmp, ranges[i], io_u_lat_u[i]);
	}
	/* Millisecond latency */
	tmp = json_create_object();
	json_object_add_value_object(root, "latency_ms", tmp);
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++) {
		const char *ranges[] = { "2", "4", "10", "20", "50", "100",
				 "250", "500", "750", "1000", "2000",
				 ">=2000", };
		json_object_add_value_float(tmp, ranges[i], io_u_lat_m[i]);
	}

	/* Additional output if continue_on_error set - default off*/
	if (ts->continue_on_error) {
		json_object_add_value_int(root, "total_err", ts->total_err_count);
		json_object_add_value_int(root, "first_error", ts->first_error);
	}

	if (ts->latency_depth) {
		json_object_add_value_int(root, "latency_depth", ts->latency_depth);
		json_object_add_value_int(root, "latency_target", ts->latency_target);
		json_object_add_value_float(root, "latency_percentile", ts->latency_percentile.u.f);
		json_object_add_value_int(root, "latency_window", ts->latency_window);
	}

	/* Additional output if description is set */
	if (strlen(ts->description))
		json_object_add_value_string(root, "desc", ts->description);

	if (ts->nr_block_infos) {
		/* Block error histogram and types */
		int len;
		unsigned int *percentiles = NULL;
		unsigned int block_state_counts[BLOCK_STATE_COUNT];

		len = calc_block_percentiles(ts->nr_block_infos, ts->block_infos,
					     ts->percentile_list,
					     &percentiles, block_state_counts);

		if (len) {
			struct json_object *block, *percentile_object, *states;
			int state;
			block = json_create_object();
			json_object_add_value_object(root, "block", block);

			percentile_object = json_create_object();
			json_object_add_value_object(block, "percentiles",
						     percentile_object);
			for (i = 0; i < len; i++) {
				char buf[20];
				snprintf(buf, sizeof(buf), "%f",
					 ts->percentile_list[i].u.f);
				json_object_add_value_int(percentile_object,
							  buf,
							  percentiles[i]);
			}

			states = json_create_object();
			json_object_add_value_object(block, "states", states);
			for (state = 0; state < BLOCK_STATE_COUNT; state++) {
				json_object_add_value_int(states,
					block_state_names[state],
					block_state_counts[state]);
			}
			free(percentiles);
		}
	}

	if (ts->ss_dur) {
		struct json_object *data;
		struct json_array *iops, *bw;
		int j, k, l;
		char ss_buf[64];
		int intervals = ts->ss_dur / (ss_check_interval / 1000L);

		snprintf(ss_buf, sizeof(ss_buf), "%s%s:%f%s",
			ts->ss_state & FIO_SS_IOPS ? "iops" : (ts->ss_state & FIO_SS_LAT ? "lat" : "bw"),
			ts->ss_state & FIO_SS_SLOPE ? "_slope" : "",
			(float) ts->ss_limit.u.f,
			ts->ss_state & FIO_SS_PCT ? "%" : "");

		tmp = json_create_object();
		json_object_add_value_object(root, "steadystate", tmp);
		json_object_add_value_string(tmp, "ss", ss_buf);
		json_object_add_value_int(tmp, "duration", (int)ts->ss_dur);
		json_object_add_value_int(tmp, "attained", (ts->ss_state & FIO_SS_ATTAINED) > 0);

		snprintf(ss_buf, sizeof(ss_buf), "%f%s", (float) ts->ss_criterion.u.f,
			ts->ss_state & FIO_SS_PCT ? "%" : "");
		json_object_add_value_string(tmp, "criterion", ss_buf);
		json_object_add_value_float(tmp, "max_deviation", ts->ss_deviation.u.f);
		json_object_add_value_float(tmp, "slope", ts->ss_slope.u.f);

		data = json_create_object();
		json_object_add_value_object(tmp, "data", data);
		bw = json_create_array();
		iops = json_create_array();

		/*
		** if ss was attained or the buffer is not full,
		** ss->head points to the first element in the list.
		** otherwise it actually points to the second element
		** in the list
		*/
		if ((ts->ss_state & FIO_SS_ATTAINED) || !(ts->ss_state & FIO_SS_BUFFER_FULL))
			j = ts->ss_head;
		else
			j = ts->ss_head == 0 ? intervals - 1 : ts->ss_head - 1;
		for (l = 0; l < intervals; l++) {
			k = (j + l) % intervals;
			json_array_add_value_int(bw, ts->ss_bw_data[k]);
			json_array_add_value_int(iops, ts->ss_iops_data[k]);
		}
		json_object_add_value_int(data, "bw_mean", steadystate_bw_mean(ts));
		json_object_add_value_int(data, "iops_mean", steadystate_iops_mean(ts));
		if (ts->ss_state & FIO_SS_LAT) {
			struct json_array *lat;
			lat = json_create_array();
			for (l = 0; l < intervals; l++) {
				k = (j + l) % intervals;
				json_array_add_value_int(lat, ts->ss_lat_data[k]);
			}
			json_object_add_value_int(data, "lat_mean", steadystate_lat_mean(ts));
			json_object_add_value_array(data, "lat_ns", lat);
		}
		json_object_add_value_array(data, "iops", iops);
		json_object_add_value_array(data, "bw", bw);
	}

	if (ts->count_zone_resets)
		json_object_add_value_int(root, "zone_resets",
					  ts->nr_zone_resets);

	return root;
}

static void show_thread_status_terse(struct thread_stat *ts,
				     struct group_run_stats *rs,
				     struct buf_output *out)
{
	if (terse_version >= 2 && terse_version <= 5)
		show_thread_status_terse_all(ts, rs, terse_version, out);
	else
		log_err("fio: bad terse version!? %d\n", terse_version);
}

struct json_object *show_thread_status(struct thread_stat *ts,
				       struct group_run_stats *rs,
				       struct flist_head *opt_list,
				       struct buf_output *out)
{
	struct json_object *ret = NULL;

	if (output_format & FIO_OUTPUT_TERSE)
		show_thread_status_terse(ts, rs,  out);
	if (output_format & FIO_OUTPUT_JSON)
		ret = show_thread_status_json(ts, rs, opt_list);
	if (output_format & FIO_OUTPUT_NORMAL)
		show_thread_status_normal(ts, rs,  out);

	return ret;
}

static void __sum_stat(struct io_stat *dst, const struct io_stat *src, bool first)
{
	double mean, S;

	dst->min_val = min(dst->min_val, src->min_val);
	dst->max_val = max(dst->max_val, src->max_val);

	/*
	 * Compute new mean and S after the merge
	 * <http://en.wikipedia.org/wiki/Algorithms_for_calculating_variance
	 *  #Parallel_algorithm>
	 */
	if (first) {
		mean = src->mean.u.f;
		S = src->S.u.f;
	} else {
		double delta = src->mean.u.f - dst->mean.u.f;

		mean = ((src->mean.u.f * src->samples) +
			(dst->mean.u.f * dst->samples)) /
			(dst->samples + src->samples);

		S =  src->S.u.f + dst->S.u.f + pow(delta, 2.0) *
			(dst->samples * src->samples) /
			(dst->samples + src->samples);
	}

	dst->samples += src->samples;
	dst->mean.u.f = mean;
	dst->S.u.f = S;

}

/*
 * We sum two kinds of stats - one that is time based, in which case we
 * apply the proper summing technique, and then one that is iops/bw
 * numbers. For group_reporting, we should just add those up, not make
 * them the mean of everything.
 */
static void sum_stat(struct io_stat *dst, const struct io_stat *src, bool pure_sum)
{
	bool first = dst->samples == 0;

	if (src->samples == 0)
		return;

	if (!pure_sum) {
		__sum_stat(dst, src, first);
		return;
	}

	if (first) {
		dst->min_val = src->min_val;
		dst->max_val = src->max_val;
		dst->samples = src->samples;
		dst->mean.u.f = src->mean.u.f;
		dst->S.u.f = src->S.u.f;
	} else {
		dst->min_val += src->min_val;
		dst->max_val += src->max_val;
		dst->samples += src->samples;
		dst->mean.u.f += src->mean.u.f;
		dst->S.u.f += src->S.u.f;
	}
}

void sum_group_stats(struct group_run_stats *dst, const struct group_run_stats *src)
{
	unsigned int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (dst->max_run[i] < src->max_run[i])
			dst->max_run[i] = src->max_run[i];
		if (dst->min_run[i] && dst->min_run[i] > src->min_run[i])
			dst->min_run[i] = src->min_run[i];
		if (dst->max_bw[i] < src->max_bw[i])
			dst->max_bw[i] = src->max_bw[i];
		if (dst->min_bw[i] && dst->min_bw[i] > src->min_bw[i])
			dst->min_bw[i] = src->min_bw[i];

		dst->iobytes[i] += src->iobytes[i];
		dst->agg[i] += src->agg[i];
	}

	if (!dst->kb_base)
		dst->kb_base = src->kb_base;
	if (!dst->unit_base)
		dst->unit_base = src->unit_base;
	if (!dst->sig_figs)
		dst->sig_figs = src->sig_figs;
}

/*
 * Free the clat_prio_stat arrays allocated by alloc_clat_prio_stat_ddir().
 */
void free_clat_prio_stats(struct thread_stat *ts)
{
	enum fio_ddir ddir;

	if (!ts)
		return;

	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
		sfree(ts->clat_prio[ddir]);
		ts->clat_prio[ddir] = NULL;
		ts->nr_clat_prio[ddir] = 0;
	}
}

/*
 * Allocate a clat_prio_stat array. The array has to be allocated/freed using
 * smalloc/sfree, so that it is accessible by the process/thread summing the
 * thread_stats.
 */
int alloc_clat_prio_stat_ddir(struct thread_stat *ts, enum fio_ddir ddir,
			      int nr_prios)
{
	struct clat_prio_stat *clat_prio;
	int i;

	clat_prio = scalloc(nr_prios, sizeof(*ts->clat_prio[ddir]));
	if (!clat_prio) {
		log_err("fio: failed to allocate ts clat data\n");
		return 1;
	}

	for (i = 0; i < nr_prios; i++)
		clat_prio[i].clat_stat.min_val = ULONG_MAX;

	ts->clat_prio[ddir] = clat_prio;
	ts->nr_clat_prio[ddir] = nr_prios;

	return 0;
}

static int grow_clat_prio_stat(struct thread_stat *dst, enum fio_ddir ddir)
{
	int curr_len = dst->nr_clat_prio[ddir];
	void *new_arr;

	new_arr = scalloc(curr_len + 1, sizeof(*dst->clat_prio[ddir]));
	if (!new_arr) {
		log_err("fio: failed to grow clat prio array\n");
		return 1;
	}

	memcpy(new_arr, dst->clat_prio[ddir],
	       curr_len * sizeof(*dst->clat_prio[ddir]));
	sfree(dst->clat_prio[ddir]);

	dst->clat_prio[ddir] = new_arr;
	dst->clat_prio[ddir][curr_len].clat_stat.min_val = ULONG_MAX;
	dst->nr_clat_prio[ddir]++;

	return 0;
}

static int find_clat_prio_index(struct thread_stat *dst, enum fio_ddir ddir,
				uint32_t ioprio)
{
	int i, nr_prios = dst->nr_clat_prio[ddir];

	for (i = 0; i < nr_prios; i++) {
		if (dst->clat_prio[ddir][i].ioprio == ioprio)
			return i;
	}

	return -1;
}

static int alloc_or_get_clat_prio_index(struct thread_stat *dst,
					enum fio_ddir ddir, uint32_t ioprio,
					int *idx)
{
	int index = find_clat_prio_index(dst, ddir, ioprio);

	if (index == -1) {
		index = dst->nr_clat_prio[ddir];

		if (grow_clat_prio_stat(dst, ddir))
			return 1;

		dst->clat_prio[ddir][index].ioprio = ioprio;
	}

	*idx = index;

	return 0;
}

static int clat_prio_stats_copy(struct thread_stat *dst, const struct thread_stat *src,
				enum fio_ddir dst_ddir, enum fio_ddir src_ddir)
{
	size_t sz = sizeof(*src->clat_prio[src_ddir]) *
		src->nr_clat_prio[src_ddir];

	dst->clat_prio[dst_ddir] = smalloc(sz);
	if (!dst->clat_prio[dst_ddir]) {
		log_err("fio: failed to alloc clat prio array\n");
		return 1;
	}

	memcpy(dst->clat_prio[dst_ddir], src->clat_prio[src_ddir], sz);
	dst->nr_clat_prio[dst_ddir] = src->nr_clat_prio[src_ddir];

	return 0;
}

static int clat_prio_stat_add_samples(struct thread_stat *dst,
				      enum fio_ddir dst_ddir, uint32_t ioprio,
				      const struct io_stat *io_stat,
				      const uint64_t *io_u_plat)
{
	int i, dst_index;

	if (!io_stat->samples)
		return 0;

	if (alloc_or_get_clat_prio_index(dst, dst_ddir, ioprio, &dst_index))
		return 1;

	sum_stat(&dst->clat_prio[dst_ddir][dst_index].clat_stat, io_stat,
		 false);

	for (i = 0; i < FIO_IO_U_PLAT_NR; i++)
		dst->clat_prio[dst_ddir][dst_index].io_u_plat[i] += io_u_plat[i];

	return 0;
}

static int sum_clat_prio_stats_src_single_prio(struct thread_stat *dst,
					       const struct thread_stat *src,
					       enum fio_ddir dst_ddir,
					       enum fio_ddir src_ddir)
{
	const struct io_stat *io_stat;
	const uint64_t *io_u_plat;

	/*
	 * If src ts has no clat_prio_stat array, then all I/Os were submitted
	 * using src->ioprio. Thus, the global samples in src->clat_stat (or
	 * src->lat_stat) can be used as the 'per prio' samples for src->ioprio.
	 */
	assert(!src->clat_prio[src_ddir]);
	assert(src->nr_clat_prio[src_ddir] == 0);

	if (src->lat_percentiles) {
		io_u_plat = src->io_u_plat[FIO_LAT][src_ddir];
		io_stat = &src->lat_stat[src_ddir];
	} else {
		io_u_plat = src->io_u_plat[FIO_CLAT][src_ddir];
		io_stat = &src->clat_stat[src_ddir];
	}

	return clat_prio_stat_add_samples(dst, dst_ddir, src->ioprio, io_stat,
					  io_u_plat);
}

static int sum_clat_prio_stats_src_multi_prio(struct thread_stat *dst,
					      const struct thread_stat *src,
					      enum fio_ddir dst_ddir,
					      enum fio_ddir src_ddir)
{
	int i;

	/*
	 * If src ts has a clat_prio_stat array, then there are multiple prios
	 * in use (i.e. src ts had cmdprio_percentage or cmdprio_bssplit set).
	 * The samples for the default prio will exist in the src->clat_prio
	 * array, just like the samples for any other prio.
	 */
	assert(src->clat_prio[src_ddir]);
	assert(src->nr_clat_prio[src_ddir]);

	/* If the dst ts doesn't yet have a clat_prio array, simply memcpy. */
	if (!dst->clat_prio[dst_ddir])
		return clat_prio_stats_copy(dst, src, dst_ddir, src_ddir);

	/* The dst ts already has a clat_prio_array, add src stats into it. */
	for (i = 0; i < src->nr_clat_prio[src_ddir]; i++) {
		struct io_stat *io_stat = &src->clat_prio[src_ddir][i].clat_stat;
		uint64_t *io_u_plat = src->clat_prio[src_ddir][i].io_u_plat;
		uint32_t ioprio = src->clat_prio[src_ddir][i].ioprio;

		if (clat_prio_stat_add_samples(dst, dst_ddir, ioprio, io_stat, io_u_plat))
			return 1;
	}

	return 0;
}

static int sum_clat_prio_stats(struct thread_stat *dst, const struct thread_stat *src,
			       enum fio_ddir dst_ddir, enum fio_ddir src_ddir)
{
	if (dst->disable_prio_stat)
		return 0;

	if (!src->clat_prio[src_ddir])
		return sum_clat_prio_stats_src_single_prio(dst, src, dst_ddir,
							   src_ddir);

	return sum_clat_prio_stats_src_multi_prio(dst, src, dst_ddir, src_ddir);
}

void sum_thread_stats(struct thread_stat *dst, const struct thread_stat *src)
{
	int k, l, m;

	for (l = 0; l < DDIR_RWDIR_CNT; l++) {
		if (dst->unified_rw_rep != UNIFIED_MIXED) {
			sum_stat(&dst->clat_stat[l], &src->clat_stat[l], false);
			sum_stat(&dst->slat_stat[l], &src->slat_stat[l], false);
			sum_stat(&dst->lat_stat[l], &src->lat_stat[l], false);
			sum_stat(&dst->bw_stat[l], &src->bw_stat[l], true);
			sum_stat(&dst->iops_stat[l], &src->iops_stat[l], true);
			sum_clat_prio_stats(dst, src, l, l);

			dst->io_bytes[l] += src->io_bytes[l];

			if (dst->runtime[l] < src->runtime[l])
				dst->runtime[l] = src->runtime[l];
		} else {
			sum_stat(&dst->clat_stat[0], &src->clat_stat[l], false);
			sum_stat(&dst->slat_stat[0], &src->slat_stat[l], false);
			sum_stat(&dst->lat_stat[0], &src->lat_stat[l], false);
			sum_stat(&dst->bw_stat[0], &src->bw_stat[l], true);
			sum_stat(&dst->iops_stat[0], &src->iops_stat[l], true);
			sum_clat_prio_stats(dst, src, 0, l);

			dst->io_bytes[0] += src->io_bytes[l];

			if (dst->runtime[0] < src->runtime[l])
				dst->runtime[0] = src->runtime[l];
		}
	}

	sum_stat(&dst->sync_stat, &src->sync_stat, false);
	dst->usr_time += src->usr_time;
	dst->sys_time += src->sys_time;
	dst->ctx += src->ctx;
	dst->majf += src->majf;
	dst->minf += src->minf;

	for (k = 0; k < FIO_IO_U_MAP_NR; k++) {
		dst->io_u_map[k] += src->io_u_map[k];
		dst->io_u_submit[k] += src->io_u_submit[k];
		dst->io_u_complete[k] += src->io_u_complete[k];
	}

	for (k = 0; k < FIO_IO_U_LAT_N_NR; k++)
		dst->io_u_lat_n[k] += src->io_u_lat_n[k];
	for (k = 0; k < FIO_IO_U_LAT_U_NR; k++)
		dst->io_u_lat_u[k] += src->io_u_lat_u[k];
	for (k = 0; k < FIO_IO_U_LAT_M_NR; k++)
		dst->io_u_lat_m[k] += src->io_u_lat_m[k];

	for (k = 0; k < DDIR_RWDIR_CNT; k++) {
		if (dst->unified_rw_rep != UNIFIED_MIXED) {
			dst->total_io_u[k] += src->total_io_u[k];
			dst->short_io_u[k] += src->short_io_u[k];
			dst->drop_io_u[k] += src->drop_io_u[k];
		} else {
			dst->total_io_u[0] += src->total_io_u[k];
			dst->short_io_u[0] += src->short_io_u[k];
			dst->drop_io_u[0] += src->drop_io_u[k];
		}
	}

	dst->total_io_u[DDIR_SYNC] += src->total_io_u[DDIR_SYNC];

	for (k = 0; k < FIO_LAT_CNT; k++)
		for (l = 0; l < DDIR_RWDIR_CNT; l++)
			for (m = 0; m < FIO_IO_U_PLAT_NR; m++)
				if (dst->unified_rw_rep != UNIFIED_MIXED)
					dst->io_u_plat[k][l][m] += src->io_u_plat[k][l][m];
				else
					dst->io_u_plat[k][0][m] += src->io_u_plat[k][l][m];

	for (k = 0; k < FIO_IO_U_PLAT_NR; k++)
		dst->io_u_sync_plat[k] += src->io_u_sync_plat[k];

	dst->total_run_time += src->total_run_time;
	dst->total_submit += src->total_submit;
	dst->total_complete += src->total_complete;
	if (src->count_zone_resets) {
		dst->count_zone_resets = 1;
		dst->nr_zone_resets += src->nr_zone_resets;
	}
	dst->cachehit += src->cachehit;
	dst->cachemiss += src->cachemiss;
}

void init_group_run_stat(struct group_run_stats *gs)
{
	int i;
	memset(gs, 0, sizeof(*gs));

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		gs->min_bw[i] = gs->min_run[i] = ~0UL;
}

void init_thread_stat_min_vals(struct thread_stat *ts)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		ts->clat_stat[i].min_val = ULONG_MAX;
		ts->slat_stat[i].min_val = ULONG_MAX;
		ts->lat_stat[i].min_val = ULONG_MAX;
		ts->bw_stat[i].min_val = ULONG_MAX;
		ts->iops_stat[i].min_val = ULONG_MAX;
	}
	ts->sync_stat.min_val = ULONG_MAX;
}

void init_thread_stat(struct thread_stat *ts)
{
	memset(ts, 0, sizeof(*ts));

	init_thread_stat_min_vals(ts);
	ts->groupid = -1;
}

static void init_per_prio_stats(struct thread_stat *threadstats, int nr_ts)
{
	struct thread_stat *ts;
	int i, j, last_ts, idx;
	enum fio_ddir ddir;

	j = 0;
	last_ts = -1;
	idx = 0;

	/*
	 * Loop through all tds, if a td requires per prio stats, temporarily
	 * store a 1 in ts->disable_prio_stat, and then do an additional
	 * loop at the end where we invert the ts->disable_prio_stat values.
	 */
	for_each_td(td) {
		if (!td->o.stats)
			continue;
		if (idx &&
		    (!td->o.group_reporting ||
		     (td->o.group_reporting && last_ts != td->groupid))) {
			idx = 0;
			j++;
		}

		last_ts = td->groupid;
		ts = &threadstats[j];

		/* idx == 0 means first td in group, or td is not in a group. */
		if (idx == 0)
			ts->ioprio = td->ioprio;
		else if (td->ioprio != ts->ioprio)
			ts->disable_prio_stat = 1;

		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			if (td->ts.clat_prio[ddir]) {
				ts->disable_prio_stat = 1;
				break;
			}
		}

		idx++;
	} end_for_each();

	/* Loop through all dst threadstats and fixup the values. */
	for (i = 0; i < nr_ts; i++) {
		ts = &threadstats[i];
		ts->disable_prio_stat = !ts->disable_prio_stat;
	}
}

void __show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_stat *threadstats, *ts;
	int i, j, k, nr_ts, last_ts, idx;
	bool kb_base_warned = false;
	bool unit_base_warned = false;
	struct json_object *root = NULL;
	struct json_array *array = NULL;
	struct buf_output output[FIO_OUTPUT_NR];
	struct flist_head **opt_lists;

	runstats = malloc(sizeof(struct group_run_stats) * (groupid + 1));

	for (i = 0; i < groupid + 1; i++)
		init_group_run_stat(&runstats[i]);

	/*
	 * find out how many threads stats we need. if group reporting isn't
	 * enabled, it's one-per-td.
	 */
	nr_ts = 0;
	last_ts = -1;
	for_each_td(td) {
		if (!td->o.group_reporting) {
			nr_ts++;
			continue;
		}
		if (last_ts == td->groupid)
			continue;
		if (!td->o.stats)
			continue;

		last_ts = td->groupid;
		nr_ts++;
	} end_for_each();

	threadstats = malloc(nr_ts * sizeof(struct thread_stat));
	opt_lists = malloc(nr_ts * sizeof(struct flist_head *));

	for (i = 0; i < nr_ts; i++) {
		init_thread_stat(&threadstats[i]);
		opt_lists[i] = NULL;
	}

	init_per_prio_stats(threadstats, nr_ts);

	j = 0;
	last_ts = -1;
	idx = 0;
	for_each_td(td) {
		if (!td->o.stats)
			continue;
		if (idx && (!td->o.group_reporting ||
		    (td->o.group_reporting && last_ts != td->groupid))) {
			idx = 0;
			j++;
		}

		last_ts = td->groupid;

		ts = &threadstats[j];

		ts->clat_percentiles = td->o.clat_percentiles;
		ts->lat_percentiles = td->o.lat_percentiles;
		ts->slat_percentiles = td->o.slat_percentiles;
		ts->percentile_precision = td->o.percentile_precision;
		memcpy(ts->percentile_list, td->o.percentile_list, sizeof(td->o.percentile_list));
		opt_lists[j] = &td->opt_list;

		idx++;

		if (ts->groupid == -1) {
			/*
			 * These are per-group shared already
			 */
			snprintf(ts->name, sizeof(ts->name), "%s", td->o.name);
			if (td->o.description)
				snprintf(ts->description,
					 sizeof(ts->description), "%s",
					 td->o.description);
			else
				memset(ts->description, 0, FIO_JOBDESC_SIZE);

			/*
			 * If multiple entries in this group, this is
			 * the first member.
			 */
			ts->thread_number = td->thread_number;
			ts->groupid = td->groupid;
			ts->job_start = td->job_start;

			/*
			 * first pid in group, not very useful...
			 */
			ts->pid = td->pid;

			ts->kb_base = td->o.kb_base;
			ts->unit_base = td->o.unit_base;
			ts->sig_figs = td->o.sig_figs;
			ts->unified_rw_rep = td->o.unified_rw_rep;
		} else if (ts->kb_base != td->o.kb_base && !kb_base_warned) {
			log_info("fio: kb_base differs for jobs in group, using"
				 " %u as the base\n", ts->kb_base);
			kb_base_warned = true;
		} else if (ts->unit_base != td->o.unit_base && !unit_base_warned) {
			log_info("fio: unit_base differs for jobs in group, using"
				 " %u as the base\n", ts->unit_base);
			unit_base_warned = true;
		}

		ts->continue_on_error = td->o.continue_on_error;
		ts->total_err_count += td->total_err_count;
		ts->first_error = td->first_error;
		if (!ts->error) {
			if (!td->error && td->o.continue_on_error &&
			    td->first_error) {
				ts->error = td->first_error;
				snprintf(ts->verror, sizeof(ts->verror), "%s",
					 td->verror);
			} else  if (td->error) {
				ts->error = td->error;
				snprintf(ts->verror, sizeof(ts->verror), "%s",
					 td->verror);
			}
		}

		ts->latency_depth = td->latency_qd;
		ts->latency_target = td->o.latency_target;
		ts->latency_percentile = td->o.latency_percentile;
		ts->latency_window = td->o.latency_window;

		ts->nr_block_infos = td->ts.nr_block_infos;
		for (k = 0; k < ts->nr_block_infos; k++)
			ts->block_infos[k] = td->ts.block_infos[k];

		sum_thread_stats(ts, &td->ts);

		ts->members++;

		if (td->o.ss_dur) {
			ts->ss_state = td->ss.state;
			ts->ss_dur = td->ss.dur;
			ts->ss_head = td->ss.head;
			ts->ss_bw_data = td->ss.bw_data;
			ts->ss_iops_data = td->ss.iops_data;
			ts->ss_lat_data = td->ss.lat_data;
			ts->ss_limit.u.f = td->ss.limit;
			ts->ss_slope.u.f = td->ss.slope;
			ts->ss_deviation.u.f = td->ss.deviation;
			ts->ss_criterion.u.f = td->ss.criterion;
		}
		else
			ts->ss_dur = ts->ss_state = 0;
	} end_for_each();

	for (i = 0; i < nr_ts; i++) {
		unsigned long long bw;

		ts = &threadstats[i];
		if (ts->groupid == -1)
			continue;
		rs = &runstats[ts->groupid];
		rs->kb_base = ts->kb_base;
		rs->unit_base = ts->unit_base;
		rs->sig_figs = ts->sig_figs;
		rs->unified_rw_rep |= ts->unified_rw_rep;

		for (j = 0; j < DDIR_RWDIR_CNT; j++) {
			if (!ts->runtime[j])
				continue;
			if (ts->runtime[j] < rs->min_run[j] || !rs->min_run[j])
				rs->min_run[j] = ts->runtime[j];
			if (ts->runtime[j] > rs->max_run[j])
				rs->max_run[j] = ts->runtime[j];

			bw = 0;
			if (ts->runtime[j])
				bw = ts->io_bytes[j] * 1000 / ts->runtime[j];
			if (bw < rs->min_bw[j])
				rs->min_bw[j] = bw;
			if (bw > rs->max_bw[j])
				rs->max_bw[j] = bw;

			rs->iobytes[j] += ts->io_bytes[j];
		}
	}

	for (i = 0; i < groupid + 1; i++) {
		enum fio_ddir ddir;

		rs = &runstats[i];

		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			if (rs->max_run[ddir])
				rs->agg[ddir] = (rs->iobytes[ddir] * 1000) /
						rs->max_run[ddir];
		}
	}

	for (i = 0; i < FIO_OUTPUT_NR; i++)
		buf_output_init(&output[i]);

	/*
	 * don't overwrite last signal output
	 */
	if (output_format & FIO_OUTPUT_NORMAL)
		log_buf(&output[__FIO_OUTPUT_NORMAL], "\n");
	if (output_format & FIO_OUTPUT_JSON) {
		struct thread_data *global;
		char time_buf[32];
		struct timeval now;
		unsigned long long ms_since_epoch;
		time_t tv_sec;

		gettimeofday(&now, NULL);
		ms_since_epoch = (unsigned long long)(now.tv_sec) * 1000 +
		                 (unsigned long long)(now.tv_usec) / 1000;

		tv_sec = now.tv_sec;
		os_ctime_r(&tv_sec, time_buf, sizeof(time_buf));
		if (time_buf[strlen(time_buf) - 1] == '\n')
			time_buf[strlen(time_buf) - 1] = '\0';

		root = json_create_object();
		json_object_add_value_string(root, "fio version", fio_version_string);
		json_object_add_value_int(root, "timestamp", now.tv_sec);
		json_object_add_value_int(root, "timestamp_ms", ms_since_epoch);
		json_object_add_value_string(root, "time", time_buf);
		global = get_global_options();
		json_add_job_opts(root, "global options", &global->opt_list);
		array = json_create_array();
		json_object_add_value_array(root, "jobs", array);
	}

	if (is_backend)
		fio_server_send_job_options(&get_global_options()->opt_list, -1U);

	for (i = 0; i < nr_ts; i++) {
		ts = &threadstats[i];
		rs = &runstats[ts->groupid];

		if (is_backend) {
			fio_server_send_job_options(opt_lists[i], i);
			fio_server_send_ts(ts, rs);
		} else {
			if (output_format & FIO_OUTPUT_TERSE)
				show_thread_status_terse(ts, rs, &output[__FIO_OUTPUT_TERSE]);
			if (output_format & FIO_OUTPUT_JSON) {
				struct json_object *tmp = show_thread_status_json(ts, rs, opt_lists[i]);
				json_array_add_value_object(array, tmp);
			}
			if (output_format & FIO_OUTPUT_NORMAL)
				show_thread_status_normal(ts, rs, &output[__FIO_OUTPUT_NORMAL]);
		}
	}
	if (!is_backend && (output_format & FIO_OUTPUT_JSON)) {
		/* disk util stats, if any */
		show_disk_util(1, root, &output[__FIO_OUTPUT_JSON]);

		show_idle_prof_stats(FIO_OUTPUT_JSON, root, &output[__FIO_OUTPUT_JSON]);

		json_print_object(root, &output[__FIO_OUTPUT_JSON]);
		log_buf(&output[__FIO_OUTPUT_JSON], "\n");
		json_free_object(root);
	}

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		rs->groupid = i;
		if (is_backend)
			fio_server_send_gs(rs);
		else if (output_format & FIO_OUTPUT_NORMAL)
			show_group_stats(rs, &output[__FIO_OUTPUT_NORMAL]);
	}

	if (is_backend)
		fio_server_send_du();
	else if (output_format & FIO_OUTPUT_NORMAL) {
		show_disk_util(0, NULL, &output[__FIO_OUTPUT_NORMAL]);
		show_idle_prof_stats(FIO_OUTPUT_NORMAL, NULL, &output[__FIO_OUTPUT_NORMAL]);
	}

	for (i = 0; i < FIO_OUTPUT_NR; i++) {
		struct buf_output *out = &output[i];

		log_info_buf(out->buf, out->buflen);
		buf_output_free(out);
	}

	fio_idle_prof_cleanup();

	log_info_flush();
	free(runstats);

	/* free arrays allocated by sum_thread_stats(), if any */
	for (i = 0; i < nr_ts; i++) {
		ts = &threadstats[i];
		free_clat_prio_stats(ts);
	}
	free(threadstats);
	free(opt_lists);
}

int __show_running_run_stats(void)
{
	unsigned long long *rt;
	struct timespec ts;

	fio_sem_down(stat_sem);

	rt = malloc(thread_number * sizeof(unsigned long long));
	fio_gettime(&ts, NULL);

	for_each_td(td) {
		if (td->runstate >= TD_EXITED)
			continue;

		td->update_rusage = 1;
		for_each_rw_ddir(ddir) {
			td->ts.io_bytes[ddir] = td->io_bytes[ddir];
		}
		td->ts.total_run_time = mtime_since(&td->epoch, &ts);

		rt[__td_index] = mtime_since(&td->start, &ts);
		if (td_read(td) && td->ts.io_bytes[DDIR_READ])
			td->ts.runtime[DDIR_READ] += rt[__td_index];
		if (td_write(td) && td->ts.io_bytes[DDIR_WRITE])
			td->ts.runtime[DDIR_WRITE] += rt[__td_index];
		if (td_trim(td) && td->ts.io_bytes[DDIR_TRIM])
			td->ts.runtime[DDIR_TRIM] += rt[__td_index];
	} end_for_each();

	for_each_td(td) {
		if (td->runstate >= TD_EXITED)
			continue;
		if (td->rusage_sem) {
			td->update_rusage = 1;
			fio_sem_down(td->rusage_sem);
		}
		td->update_rusage = 0;
	} end_for_each();

	__show_run_stats();

	for_each_td(td) {
		if (td->runstate >= TD_EXITED)
			continue;

		if (td_read(td) && td->ts.io_bytes[DDIR_READ])
			td->ts.runtime[DDIR_READ] -= rt[__td_index];
		if (td_write(td) && td->ts.io_bytes[DDIR_WRITE])
			td->ts.runtime[DDIR_WRITE] -= rt[__td_index];
		if (td_trim(td) && td->ts.io_bytes[DDIR_TRIM])
			td->ts.runtime[DDIR_TRIM] -= rt[__td_index];
	} end_for_each();

	free(rt);
	fio_sem_up(stat_sem);

	return 0;
}

static bool status_file_disabled;

#define FIO_STATUS_FILE		"fio-dump-status"

static int check_status_file(void)
{
	struct stat sb;
	const char *temp_dir;
	char fio_status_file_path[PATH_MAX];

	if (status_file_disabled)
		return 0;

	temp_dir = getenv("TMPDIR");
	if (temp_dir == NULL) {
		temp_dir = getenv("TEMP");
		if (temp_dir && strlen(temp_dir) >= PATH_MAX)
			temp_dir = NULL;
	}
	if (temp_dir == NULL)
		temp_dir = "/tmp";
#ifdef __COVERITY__
	__coverity_tainted_data_sanitize__(temp_dir);
#endif

	snprintf(fio_status_file_path, sizeof(fio_status_file_path), "%s/%s", temp_dir, FIO_STATUS_FILE);

	if (stat(fio_status_file_path, &sb))
		return 0;

	if (unlink(fio_status_file_path) < 0) {
		log_err("fio: failed to unlink %s: %s\n", fio_status_file_path,
							strerror(errno));
		log_err("fio: disabling status file updates\n");
		status_file_disabled = true;
	}

	return 1;
}

void check_for_running_stats(void)
{
	if (check_status_file()) {
		show_running_run_stats();
		return;
	}
}

static inline void add_stat_sample(struct io_stat *is, unsigned long long data)
{
	double val = data;
	double delta;

	if (data > is->max_val)
		is->max_val = data;
	if (data < is->min_val)
		is->min_val = data;

	delta = val - is->mean.u.f;
	if (delta) {
		is->mean.u.f += delta / (is->samples + 1.0);
		is->S.u.f += delta * (val - is->mean.u.f);
	}

	is->samples++;
}

static inline void add_stat_prio_sample(struct clat_prio_stat *clat_prio,
					unsigned short clat_prio_index,
					unsigned long long nsec)
{
	if (clat_prio)
		add_stat_sample(&clat_prio[clat_prio_index].clat_stat, nsec);
}

/*
 * Return a struct io_logs, which is added to the tail of the log
 * list for 'iolog'.
 */
static struct io_logs *get_new_log(struct io_log *iolog)
{
	size_t new_samples;
	struct io_logs *cur_log;

	/*
	 * Cap the size at MAX_LOG_ENTRIES, so we don't keep doubling
	 * forever
	 */
	if (!iolog->cur_log_max) {
		if (iolog->td)
			new_samples = iolog->td->o.log_entries;
		else
			new_samples = DEF_LOG_ENTRIES;
	} else {
		new_samples = iolog->cur_log_max * 2;
		if (new_samples > MAX_LOG_ENTRIES)
			new_samples = MAX_LOG_ENTRIES;
	}

	cur_log = smalloc(sizeof(*cur_log));
	if (cur_log) {
		INIT_FLIST_HEAD(&cur_log->list);
		cur_log->log = calloc(new_samples, log_entry_sz(iolog));
		if (cur_log->log) {
			cur_log->nr_samples = 0;
			cur_log->max_samples = new_samples;
			flist_add_tail(&cur_log->list, &iolog->io_logs);
			iolog->cur_log_max = new_samples;
			return cur_log;
		}
		sfree(cur_log);
	}

	return NULL;
}

/*
 * Add and return a new log chunk, or return current log if big enough
 */
static struct io_logs *regrow_log(struct io_log *iolog)
{
	struct io_logs *cur_log;
	int i;

	if (!iolog || iolog->disabled)
		goto disable;

	cur_log = iolog_cur_log(iolog);
	if (!cur_log) {
		cur_log = get_new_log(iolog);
		if (!cur_log)
			return NULL;
	}

	if (cur_log->nr_samples < cur_log->max_samples)
		return cur_log;

	/*
	 * No room for a new sample. If we're compressing on the fly, flush
	 * out the current chunk
	 */
	if (iolog->log_gz) {
		if (iolog_cur_flush(iolog, cur_log)) {
			log_err("fio: failed flushing iolog! Will stop logging.\n");
			return NULL;
		}
	}

	/*
	 * Get a new log array, and add to our list
	 */
	cur_log = get_new_log(iolog);
	if (!cur_log) {
		log_err("fio: failed extending iolog! Will stop logging.\n");
		return NULL;
	}

	if (!iolog->pending || !iolog->pending->nr_samples)
		return cur_log;

	/*
	 * Flush pending items to new log
	 */
	for (i = 0; i < iolog->pending->nr_samples; i++) {
		struct io_sample *src, *dst;

		src = get_sample(iolog, iolog->pending, i);
		dst = get_sample(iolog, cur_log, i);
		memcpy(dst, src, log_entry_sz(iolog));
	}
	cur_log->nr_samples = iolog->pending->nr_samples;

	iolog->pending->nr_samples = 0;
	return cur_log;
disable:
	if (iolog)
		iolog->disabled = true;
	return NULL;
}

void regrow_logs(struct thread_data *td)
{
	regrow_log(td->slat_log);
	regrow_log(td->clat_log);
	regrow_log(td->clat_hist_log);
	regrow_log(td->lat_log);
	regrow_log(td->bw_log);
	regrow_log(td->iops_log);
	td->flags &= ~TD_F_REGROW_LOGS;
}

void regrow_agg_logs(void)
{
	enum fio_ddir ddir;

	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++)
		regrow_log(agg_io_log[ddir]);
}

static struct io_logs *get_cur_log(struct io_log *iolog)
{
	struct io_logs *cur_log;

	cur_log = iolog_cur_log(iolog);
	if (!cur_log) {
		cur_log = get_new_log(iolog);
		if (!cur_log)
			return NULL;
	}

	if (cur_log->nr_samples < cur_log->max_samples)
		return cur_log;

	/*
	 * Out of space. If we're in IO offload mode, or we're not doing
	 * per unit logging (hence logging happens outside of the IO thread
	 * as well), add a new log chunk inline. If we're doing inline
	 * submissions, flag 'td' as needing a log regrow and we'll take
	 * care of it on the submission side.
	 */
	if ((iolog->td && iolog->td->o.io_submit_mode == IO_MODE_OFFLOAD) ||
	    !per_unit_log(iolog))
		return regrow_log(iolog);

	if (iolog->td)
		iolog->td->flags |= TD_F_REGROW_LOGS;
	if (iolog->pending)
		assert(iolog->pending->nr_samples < iolog->pending->max_samples);
	return iolog->pending;
}

static void __add_log_sample(struct io_log *iolog, unsigned long t,
			     struct log_sample *sample)
{
	struct io_logs *cur_log;

	if (iolog->disabled)
		return;
	if (flist_empty(&iolog->io_logs))
		iolog->avg_last[sample->ddir] = t;

	cur_log = get_cur_log(iolog);
	if (cur_log) {
		struct io_sample *s;

		s = get_sample(iolog, cur_log, cur_log->nr_samples);

		s->data = sample->data;
		s->time = t;
		if (iolog->td && iolog->td->o.log_alternate_epoch)
			s->time += iolog->td->alternate_epoch;
		io_sample_set_ddir(iolog, s, sample->ddir);
		s->bs = sample->bs;
		s->priority = sample->priority;

		if (iolog->log_offset)
			s->aux[IOS_AUX_OFFSET_INDEX] = sample->offset;

		if (iolog->log_issue_time)
			s->aux[IOS_AUX_ISSUE_TIME_INDEX] = sample->issue_time;

		cur_log->nr_samples++;
		return;
	}

	iolog->disabled = true;
}

static inline void reset_io_stat(struct io_stat *ios)
{
	ios->min_val = -1ULL;
	ios->max_val = ios->samples = 0;
	ios->mean.u.f = ios->S.u.f = 0;
}

static inline void reset_io_u_plat(uint64_t *io_u_plat)
{
	int i;

	for (i = 0; i < FIO_IO_U_PLAT_NR; i++)
		io_u_plat[i] = 0;
}

static inline void reset_clat_prio_stats(struct thread_stat *ts)
{
	enum fio_ddir ddir;
	int i;

	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
		if (!ts->clat_prio[ddir])
			continue;

		for (i = 0; i < ts->nr_clat_prio[ddir]; i++) {
			reset_io_stat(&ts->clat_prio[ddir][i].clat_stat);
			reset_io_u_plat(ts->clat_prio[ddir][i].io_u_plat);
		}
	}
}

void reset_io_stats(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;
	int i, j;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		reset_io_stat(&ts->clat_stat[i]);
		reset_io_stat(&ts->slat_stat[i]);
		reset_io_stat(&ts->lat_stat[i]);
		reset_io_stat(&ts->bw_stat[i]);
		reset_io_stat(&ts->iops_stat[i]);

		ts->io_bytes[i] = 0;
		ts->runtime[i] = 0;
		ts->total_io_u[i] = 0;
		ts->short_io_u[i] = 0;
		ts->drop_io_u[i] = 0;
	}

	for (i = 0; i < FIO_LAT_CNT; i++)
		for (j = 0; j < DDIR_RWDIR_CNT; j++)
			reset_io_u_plat(ts->io_u_plat[i][j]);

	reset_clat_prio_stats(ts);

	ts->total_io_u[DDIR_SYNC] = 0;
	reset_io_u_plat(ts->io_u_sync_plat);

	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		ts->io_u_map[i] = 0;
		ts->io_u_submit[i] = 0;
		ts->io_u_complete[i] = 0;
	}

	for (i = 0; i < FIO_IO_U_LAT_N_NR; i++)
		ts->io_u_lat_n[i] = 0;
	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++)
		ts->io_u_lat_u[i] = 0;
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++)
		ts->io_u_lat_m[i] = 0;

	ts->total_submit = 0;
	ts->total_complete = 0;
	ts->nr_zone_resets = 0;
	ts->cachehit = ts->cachemiss = 0;
}

static void __add_stat_to_log(struct io_log *iolog, enum fio_ddir ddir,
			      unsigned long elapsed, int log_max)
{
	/*
	 * Note an entry in the log. Use the mean from the logged samples,
	 * making sure to properly round up. Only write a log entry if we
	 * had actual samples done.
	 */
	if (iolog->avg_window[ddir].samples) {
		struct log_sample sample = { {{ 0, 0 }}, ddir, 0, 0, 0, 0 };
		union io_sample_data *d = &sample.data;

		if (log_max == IO_LOG_SAMPLE_AVG) {
			d->val.val0 = iolog->avg_window[ddir].mean.u.f + 0.50;
			d->val.val1 = 0;
		} else if (log_max == IO_LOG_SAMPLE_MAX) {
			d->val.val0 = iolog->avg_window[ddir].max_val;
			d->val.val1 = 0;
		} else {
			d->val.val0 = iolog->avg_window[ddir].mean.u.f + 0.50;
			d->val.val1 = iolog->avg_window[ddir].max_val;
		}

		__add_log_sample(iolog, elapsed, &sample);
	}

	reset_io_stat(&iolog->avg_window[ddir]);
}

static void _add_stat_to_log(struct io_log *iolog, unsigned long elapsed,
			     int log_max)
{
	enum fio_ddir ddir;

	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++)
		__add_stat_to_log(iolog, ddir, elapsed, log_max);
}

static unsigned long add_log_sample(struct thread_data *td,
				    struct io_log *iolog,
				    struct log_sample *sample)
{
	unsigned long elapsed, this_window;
	enum fio_ddir ddir = sample->ddir;

	if (!ddir_rw(ddir))
		return 0;

	elapsed = mtime_since_now(&td->epoch);

	/*
	 * If no time averaging, just add the log sample.
	 */
	if (!iolog->avg_msec) {
		__add_log_sample(iolog, elapsed, sample);
		return 0;
	}

	/*
	 * Add the sample. If the time period has passed, then
	 * add that entry to the log and clear.
	 */
	add_stat_sample(&iolog->avg_window[ddir], sample->data.val.val0);

	/*
	 * If period hasn't passed, adding the above sample is all we
	 * need to do.
	 */
	this_window = elapsed - iolog->avg_last[ddir];
	if (elapsed < iolog->avg_last[ddir])
		return iolog->avg_last[ddir] - elapsed;
	else if (this_window < iolog->avg_msec) {
		unsigned long diff = iolog->avg_msec - this_window;

		if (inline_log(iolog) || diff > LOG_MSEC_SLACK)
			return diff;
	}

	__add_stat_to_log(iolog, ddir, elapsed, td->o.log_max);

	iolog->avg_last[ddir] = elapsed - (elapsed % iolog->avg_msec);

	return iolog->avg_msec;
}

void finalize_logs(struct thread_data *td, bool unit_logs)
{
	unsigned long elapsed;

	elapsed = mtime_since_now(&td->epoch);

	if (td->clat_log && unit_logs)
		_add_stat_to_log(td->clat_log, elapsed, td->o.log_max);
	if (td->slat_log && unit_logs)
		_add_stat_to_log(td->slat_log, elapsed, td->o.log_max);
	if (td->lat_log && unit_logs)
		_add_stat_to_log(td->lat_log, elapsed, td->o.log_max);
	if (td->bw_log && (unit_logs == per_unit_log(td->bw_log)))
		_add_stat_to_log(td->bw_log, elapsed, td->o.log_max);
	if (td->iops_log && (unit_logs == per_unit_log(td->iops_log)))
		_add_stat_to_log(td->iops_log, elapsed, td->o.log_max);
}

void add_agg_sample(union io_sample_data data, enum fio_ddir ddir,
		    unsigned long long bs)
{
	struct io_log *iolog;
	struct log_sample sample = { data, ddir, bs, 0, 0, 0 };

	if (!ddir_rw(ddir))
		return;

	iolog = agg_io_log[ddir];
	__add_log_sample(iolog, mtime_since_genesis(), &sample);
}

void add_sync_clat_sample(struct thread_stat *ts, unsigned long long nsec)
{
	unsigned int idx = plat_val_to_idx(nsec);
	assert(idx < FIO_IO_U_PLAT_NR);

	ts->io_u_sync_plat[idx]++;
	add_stat_sample(&ts->sync_stat, nsec);
}

static inline void add_lat_percentile_sample(struct thread_stat *ts,
					     unsigned long long nsec,
					     enum fio_ddir ddir,
					     enum fio_lat lat)
{
	unsigned int idx = plat_val_to_idx(nsec);
	assert(idx < FIO_IO_U_PLAT_NR);

	ts->io_u_plat[lat][ddir][idx]++;
}

static inline void
add_lat_percentile_prio_sample(struct thread_stat *ts, unsigned long long nsec,
			       enum fio_ddir ddir,
			       unsigned short clat_prio_index)
{
	unsigned int idx = plat_val_to_idx(nsec);

	if (ts->clat_prio[ddir])
		ts->clat_prio[ddir][clat_prio_index].io_u_plat[idx]++;
}

void add_clat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long long nsec, unsigned long long bs,
		     struct io_u *io_u)
{
	const bool needs_lock = td_async_processing(td);
	unsigned long elapsed, this_window;
	struct thread_stat *ts = &td->ts;
	struct io_log *iolog = td->clat_hist_log;
	uint64_t offset = 0;
	unsigned int ioprio = 0;
	unsigned short clat_prio_index = 0;

	if (needs_lock)
		__td_io_u_lock(td);

	if (io_u) {
		offset = io_u->offset;
		ioprio = io_u->ioprio;
		clat_prio_index = io_u->clat_prio_index;
	}

	add_stat_sample(&ts->clat_stat[ddir], nsec);

	/*
	 * When lat_percentiles=1 (default 0), the reported per priority
	 * percentiles and stats are used for describing total latency values,
	 * even though the variable names themselves start with clat_.
	 *
	 * Because of the above definition, add a prio stat sample only when
	 * lat_percentiles=0. add_lat_sample() will add the prio stat sample
	 * when lat_percentiles=1.
	 */
	if (!ts->lat_percentiles)
		add_stat_prio_sample(ts->clat_prio[ddir], clat_prio_index,
				     nsec);

	if (td->clat_log) {
		struct log_sample sample = { sample_val(nsec), ddir, bs,
			offset, ioprio, 0 };

		if (io_u)
			sample.issue_time =
				ntime_since(&td->epoch, &io_u->issue_time);

		add_log_sample(td, td->clat_log, &sample);
	}

	if (ts->clat_percentiles) {
		/*
		 * Because of the above definition, add a prio lat percentile
		 * sample only when lat_percentiles=0. add_lat_sample() will add
		 * the prio lat percentile sample when lat_percentiles=1.
		 */
		add_lat_percentile_sample(ts, nsec, ddir, FIO_CLAT);
		if (!ts->lat_percentiles)
			add_lat_percentile_prio_sample(ts, nsec, ddir,
						       clat_prio_index);
	}

	if (iolog && iolog->hist_msec) {
		struct io_hist *hw = &iolog->hist_window[ddir];

		hw->samples++;
		elapsed = mtime_since_now(&td->epoch);
		if (!hw->hist_last)
			hw->hist_last = elapsed;
		this_window = elapsed - hw->hist_last;

		if (this_window >= iolog->hist_msec) {
			uint64_t *io_u_plat;
			struct io_u_plat_entry *dst;
			struct log_sample sample = { {{ 0, 0 }}, ddir, bs,
				offset, ioprio, 0 };

			/*
			 * Make a byte-for-byte copy of the latency histogram
			 * stored in td->ts.io_u_plat[ddir], recording it in a
			 * log sample. Note that the matching call to free() is
			 * located in iolog.c after printing this sample to the
			 * log file.
			 */
			io_u_plat = (uint64_t *) td->ts.io_u_plat[FIO_CLAT][ddir];
			dst = malloc(sizeof(struct io_u_plat_entry));
			memcpy(&(dst->io_u_plat), io_u_plat,
				FIO_IO_U_PLAT_NR * sizeof(uint64_t));
			flist_add(&dst->list, &hw->list);

			sample.data = sample_plat(dst);
			__add_log_sample(iolog, elapsed, &sample);

			/*
			 * Update the last time we recorded as being now, minus
			 * any drift in time we encountered before actually
			 * making the record.
			 */
			hw->hist_last = elapsed - (this_window - iolog->hist_msec);
			hw->samples = 0;
		}
	}

	if (needs_lock)
		__td_io_u_unlock(td);
}

void add_slat_sample(struct thread_data *td, struct io_u *io_u)
{
	const bool needs_lock = td_async_processing(td);
	struct thread_stat *ts = &td->ts;
	enum fio_ddir ddir;
	unsigned long long nsec;

	ddir = io_u->ddir;
	if (!ddir_rw(ddir))
		return;

	if (needs_lock)
		__td_io_u_lock(td);

	nsec = ntime_since(&io_u->start_time, &io_u->issue_time);

	add_stat_sample(&ts->slat_stat[ddir], nsec);

	if (td->slat_log) {
		struct log_sample sample = { sample_val(nsec), ddir,
			io_u->xfer_buflen, io_u->offset, io_u->ioprio,
			ntime_since(&td->epoch, &io_u->issue_time) };

		add_log_sample(td, td->slat_log, &sample);
	}

	if (ts->slat_percentiles)
		add_lat_percentile_sample(ts, nsec, ddir, FIO_SLAT);

	if (needs_lock)
		__td_io_u_unlock(td);
}

void add_lat_sample(struct thread_data *td, enum fio_ddir ddir,
		    unsigned long long nsec, unsigned long long bs,
		    struct io_u * io_u)
{
	const bool needs_lock = td_async_processing(td);
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	if (needs_lock)
		__td_io_u_lock(td);

	add_stat_sample(&ts->lat_stat[ddir], nsec);

	if (td->lat_log) {
		struct log_sample sample = { sample_val(nsec), ddir, bs,
			io_u->offset, io_u->ioprio, 0 };

		add_log_sample(td, td->lat_log, &sample);
	}

	/*
	 * When lat_percentiles=1 (default 0), the reported per priority
	 * percentiles and stats are used for describing total latency values,
	 * even though the variable names themselves start with clat_.
	 *
	 * Because of the above definition, add a prio stat and prio lat
	 * percentile sample only when lat_percentiles=1. add_clat_sample() will
	 * add the prio stat and prio lat percentile sample when
	 * lat_percentiles=0.
	 */
	if (ts->lat_percentiles) {
		add_lat_percentile_sample(ts, nsec, ddir, FIO_LAT);
		add_lat_percentile_prio_sample(ts, nsec, ddir,
					       io_u->clat_prio_index);
		add_stat_prio_sample(ts->clat_prio[ddir], io_u->clat_prio_index,
				     nsec);
	}
	if (needs_lock)
		__td_io_u_unlock(td);
}

void add_bw_sample(struct thread_data *td, struct io_u *io_u,
		   unsigned int bytes, unsigned long long spent)
{
	const bool needs_lock = td_async_processing(td);
	struct thread_stat *ts = &td->ts;
	unsigned long rate;

	if (spent)
		rate = (unsigned long) (bytes * 1000000ULL / spent);
	else
		rate = 0;

	if (needs_lock)
		__td_io_u_lock(td);

	add_stat_sample(&ts->bw_stat[io_u->ddir], rate);

	if (td->bw_log) {
		struct log_sample sample = { sample_val(rate), io_u->ddir,
			bytes, io_u->offset, io_u->ioprio, 0 };

		add_log_sample(td, td->bw_log, &sample);
	}

	td->stat_io_bytes[io_u->ddir] = td->this_io_bytes[io_u->ddir];

	if (needs_lock)
		__td_io_u_unlock(td);
}

static int __add_samples(struct thread_data *td, struct timespec *parent_tv,
			 struct timespec *t, unsigned int avg_time,
			 uint64_t *this_io_bytes, uint64_t *stat_io_bytes,
			 struct io_stat *stat, struct io_log *log,
			 bool is_kb)
{
	const bool needs_lock = td_async_processing(td);
	unsigned long spent, rate;
	enum fio_ddir ddir;
	unsigned long next, next_log;

	next_log = avg_time;

	spent = mtime_since(parent_tv, t);
	if (spent < avg_time && avg_time - spent > LOG_MSEC_SLACK)
		return avg_time - spent;

	if (needs_lock)
		__td_io_u_lock(td);

	/*
	 * Compute both read and write rates for the interval.
	 */
	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
		uint64_t delta;

		delta = this_io_bytes[ddir] - stat_io_bytes[ddir];
		if (!delta)
			continue; /* No entries for interval */

		if (spent) {
			if (is_kb)
				rate = delta * 1000 / spent / 1024; /* KiB/s */
			else
				rate = (delta * 1000) / spent;
		} else
			rate = 0;

		add_stat_sample(&stat[ddir], rate);

		if (log) {
			struct log_sample sample = {
				sample_val(rate), ddir, 0, 0, 0, 0 };

			if (td->o.min_bs[ddir] == td->o.max_bs[ddir])
				sample.bs = td->o.min_bs[ddir];
			next = add_log_sample(td, log, &sample);
			next_log = min(next_log, next);
		}

		stat_io_bytes[ddir] = this_io_bytes[ddir];
	}

	*parent_tv = *t;

	if (needs_lock)
		__td_io_u_unlock(td);

	if (spent <= avg_time)
		next = avg_time;
	else
		next = avg_time - (1 + spent - avg_time);

	return min(next, next_log);
}

static int add_bw_samples(struct thread_data *td, struct timespec *t)
{
	return __add_samples(td, &td->bw_sample_time, t, td->o.bw_avg_time,
				td->this_io_bytes, td->stat_io_bytes,
				td->ts.bw_stat, td->bw_log, true);
}

void add_iops_sample(struct thread_data *td, struct io_u *io_u,
		     unsigned int bytes)
{
	const bool needs_lock = td_async_processing(td);
	struct thread_stat *ts = &td->ts;

	if (needs_lock)
		__td_io_u_lock(td);

	add_stat_sample(&ts->iops_stat[io_u->ddir], 1);

	if (td->iops_log) {
		struct log_sample sample = { sample_val(1), io_u->ddir, bytes,
			io_u->offset, io_u->ioprio, 0 };

		add_log_sample(td, td->iops_log, &sample);
	}

	td->stat_io_blocks[io_u->ddir] = td->this_io_blocks[io_u->ddir];

	if (needs_lock)
		__td_io_u_unlock(td);
}

static int add_iops_samples(struct thread_data *td, struct timespec *t)
{
	return __add_samples(td, &td->iops_sample_time, t, td->o.iops_avg_time,
				td->this_io_blocks, td->stat_io_blocks,
				td->ts.iops_stat, td->iops_log, false);
}

static bool td_in_logging_state(struct thread_data *td)
{
	if (in_ramp_period(td))
		return false;

	switch(td->runstate) {
	case TD_RUNNING:
	case TD_VERIFYING:
	case TD_FINISHING:
	case TD_EXITED:
		return true;
	default:
		return false;
	}
}

/*
 * Returns msecs to next event
 */
int calc_log_samples(void)
{
	unsigned int next = ~0U, tmp = 0, next_mod = 0, log_avg_msec_min = -1U;
	struct timespec now;
	long elapsed_time = 0;

	for_each_td(td) {
		fio_gettime(&now, NULL);
		elapsed_time = mtime_since(&td->epoch, &now);

		if (!td->o.stats)
			continue;
		if (!td_in_logging_state(td)) {
			next = min(td->o.iops_avg_time, td->o.bw_avg_time);
			continue;
		}
		if (!td->bw_log ||
			(td->bw_log && !per_unit_log(td->bw_log))) {
			tmp = add_bw_samples(td, &now);

			if (td->bw_log)
				log_avg_msec_min = min(log_avg_msec_min, (unsigned int)td->bw_log->avg_msec);
		}
		if (!td->iops_log ||
			(td->iops_log && !per_unit_log(td->iops_log))) {
			tmp = add_iops_samples(td, &now);

			if (td->iops_log)
				log_avg_msec_min = min(log_avg_msec_min, (unsigned int)td->iops_log->avg_msec);
		}

		if (tmp < next)
			next = tmp;
	} end_for_each();

	/* if log_avg_msec_min has not been changed, set it to 0 */
	if (log_avg_msec_min == -1U)
		log_avg_msec_min = 0;

	if (log_avg_msec_min == 0)
		next_mod = elapsed_time;
	else
		next_mod = elapsed_time % log_avg_msec_min;

	/* correction to keep the time on the log avg msec boundary */
	next = min(next, (log_avg_msec_min - next_mod));

	return next == ~0U ? 0 : next;
}

void stat_init(void)
{
	stat_sem = fio_shared_sem_init(FIO_SEM_UNLOCKED);
}

void stat_exit(void)
{
	/*
	 * When we have the mutex, we know out-of-band access to it
	 * have ended.
	 */
	fio_sem_down(stat_sem);
	fio_shared_sem_remove(stat_sem);
}

/*
 * Called from signal handler. Wake up status thread.
 */
void show_running_run_stats(void)
{
	helper_do_stat();
}

uint32_t *io_u_block_info(struct thread_data *td, struct io_u *io_u)
{
	/* Ignore io_u's which span multiple blocks--they will just get
	 * inaccurate counts. */
	int idx = (io_u->offset - io_u->file->file_offset)
			/ td->o.bs[DDIR_TRIM];
	uint32_t *info = &td->ts.block_infos[idx];
	assert(idx < td->ts.nr_block_infos);
	return info;
}

