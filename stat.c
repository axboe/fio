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
#include "lib/ieee754.h"
#include "json.h"
#include "lib/getrusage.h"
#include "idletime.h"
#include "lib/pow2.h"
#include "lib/output_buffer.h"
#include "helper_thread.h"

struct fio_mutex *stat_mutex;

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
	ts->usr_time += mtime_since(&td->ru_start.ru_utime,
					&td->ru_end.ru_utime);
	ts->sys_time += mtime_since(&td->ru_start.ru_stime,
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
	idx = (base + offset) < (FIO_IO_U_PLAT_NR - 1) ?
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
	if (idx < (FIO_IO_U_PLAT_VAL << 1))
		return idx;

	/* Find the group and compute the minimum value of that group */
	error_bits = (idx >> FIO_IO_U_PLAT_BITS) - 1;
	base = 1 << (error_bits + FIO_IO_U_PLAT_BITS);

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

unsigned int calc_clat_percentiles(unsigned int *io_u_plat, unsigned long nr,
				   fio_fp64_t *plist, unsigned int **output,
				   unsigned int *maxv, unsigned int *minv)
{
	unsigned long sum = 0;
	unsigned int len, i, j = 0;
	unsigned int oval_len = 0;
	unsigned int *ovals = NULL;
	int is_last;

	*minv = -1U;
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
		qsort((void *)plist, len, sizeof(plist[0]), double_cmp);

	/*
	 * Calculate bucket values, note down max and min values
	 */
	is_last = 0;
	for (i = 0; i < FIO_IO_U_PLAT_NR && !is_last; i++) {
		sum += io_u_plat[i];
		while (sum >= (plist[j].u.f / 100.0 * nr)) {
			assert(plist[j].u.f <= 100.0);

			if (j == oval_len) {
				oval_len += 100;
				ovals = realloc(ovals, oval_len * sizeof(unsigned int));
			}

			ovals[j] = plat_idx_to_val(i);
			if (ovals[j] < *minv)
				*minv = ovals[j];
			if (ovals[j] > *maxv)
				*maxv = ovals[j];

			is_last = (j == len - 1);
			if (is_last)
				break;

			j++;
		}
	}

	*output = ovals;
	return len;
}

/*
 * Find and display the p-th percentile of clat
 */
static void show_clat_percentiles(unsigned int *io_u_plat, unsigned long nr,
				  fio_fp64_t *plist, unsigned int precision,
				  struct buf_output *out)
{
	unsigned int len, j = 0, minv, maxv;
	unsigned int *ovals;
	int is_last, per_line, scale_down;
	char fmt[32];

	len = calc_clat_percentiles(io_u_plat, nr, plist, &ovals, &maxv, &minv);
	if (!len)
		goto out;

	/*
	 * We default to usecs, but if the value range is such that we
	 * should scale down to msecs, do that.
	 */
	if (minv > 2000 && maxv > 99999) {
		scale_down = 1;
		log_buf(out, "    clat percentiles (msec):\n     |");
	} else {
		scale_down = 0;
		log_buf(out, "    clat percentiles (usec):\n     |");
	}

	snprintf(fmt, sizeof(fmt), "%%1.%uf", precision);
	per_line = (80 - 7) / (precision + 14);

	for (j = 0; j < len; j++) {
		char fbuf[16], *ptr = fbuf;

		/* for formatting */
		if (j != 0 && (j % per_line) == 0)
			log_buf(out, "     |");

		/* end of the list */
		is_last = (j == len - 1);

		if (plist[j].u.f < 10.0)
			ptr += sprintf(fbuf, " ");

		snprintf(ptr, sizeof(fbuf), fmt, plist[j].u.f);

		if (scale_down)
			ovals[j] = (ovals[j] + 999) / 1000;

		log_buf(out, " %sth=[%5u]%c", fbuf, ovals[j], is_last ? '\n' : ',');

		if (is_last)
			break;

		if ((j % per_line) == per_line - 1)	/* for formatting */
			log_buf(out, "\n");
	}

out:
	if (ovals)
		free(ovals);
}

int calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max,
	     double *mean, double *dev)
{
	double n = (double) is->samples;

	if (n == 0)
		return 0;

	*min = is->min_val;
	*max = is->max_val;
	*mean = is->mean.u.f;

	if (n > 1.0)
		*dev = sqrt(is->S.u.f / (n - 1.0));
	else
		*dev = 0;

	return 1;
}

void show_group_stats(struct group_run_stats *rs, struct buf_output *out)
{
	char *p1, *p2, *p3, *p4;
	const char *str[] = { "   READ", "  WRITE" , "   TRIM"};
	int i;

	log_buf(out, "\nRun status group %d (all jobs):\n", rs->groupid);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		const int i2p = is_power_of_2(rs->kb_base);

		if (!rs->max_run[i])
			continue;

		p1 = num2str(rs->io_kb[i], 6, rs->kb_base, i2p, 8);
		p2 = num2str(rs->agg[i], 6, rs->kb_base, i2p, rs->unit_base);
		p3 = num2str(rs->min_bw[i], 6, rs->kb_base, i2p, rs->unit_base);
		p4 = num2str(rs->max_bw[i], 6, rs->kb_base, i2p, rs->unit_base);

		log_buf(out, "%s: io=%s, aggrb=%s/s, minb=%s/s, maxb=%s/s,"
			 " mint=%llumsec, maxt=%llumsec\n",
				rs->unified_rw_rep ? "  MIXED" : str[i],
				p1, p2, p3, p4,
				(unsigned long long) rs->min_run[i],
				(unsigned long long) rs->max_run[i]);

		free(p1);
		free(p2);
		free(p3);
		free(p4);
	}
}

void stat_calc_dist(unsigned int *map, unsigned long total, double *io_u_dist)
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

void stat_calc_lat_u(struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_u, FIO_IO_U_LAT_U_NR);
}

void stat_calc_lat_m(struct thread_stat *ts, double *io_u_lat)
{
	stat_calc_lat(ts, io_u_lat, ts->io_u_lat_m, FIO_IO_U_LAT_M_NR);
}

static void display_lat(const char *name, unsigned long min, unsigned long max,
			double mean, double dev, struct buf_output *out)
{
	const char *base = "(usec)";
	char *minp, *maxp;

	if (!usec_to_msec(&min, &max, &mean, &dev))
		base = "(msec)";

	minp = num2str(min, 6, 1, 0, 0);
	maxp = num2str(max, 6, 1, 0, 0);

	log_buf(out, "    %s %s: min=%s, max=%s, avg=%5.02f,"
		 " stdev=%5.02f\n", name, base, minp, maxp, mean, dev);

	free(minp);
	free(maxp);
}

static void show_ddir_status(struct group_run_stats *rs, struct thread_stat *ts,
			     int ddir, struct buf_output *out)
{
	const char *str[] = { "read ", "write", "trim" };
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
	io_p = num2str(ts->io_bytes[ddir], 6, 1, i2p, 8);
	bw_p = num2str(bw, 6, 1, i2p, ts->unit_base);

	iops = (1000 * (uint64_t)ts->total_io_u[ddir]) / runt;
	iops_p = num2str(iops, 6, 1, 0, 0);

	log_buf(out, "  %s: io=%s, bw=%s/s, iops=%s, runt=%6llumsec\n",
				rs->unified_rw_rep ? "mixed" : str[ddir],
				io_p, bw_p, iops_p,
				(unsigned long long) ts->runtime[ddir]);

	free(io_p);
	free(bw_p);
	free(iops_p);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		display_lat("slat", min, max, mean, dev, out);
	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		display_lat("clat", min, max, mean, dev, out);
	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev))
		display_lat(" lat", min, max, mean, dev, out);

	if (ts->clat_percentiles) {
		show_clat_percentiles(ts->io_u_plat[ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list,
					ts->percentile_precision, out);
	}
	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg = 100.0, fkb_base = (double)rs->kb_base;
		const char *bw_str = (rs->unit_base == 1 ? "Kbit" : "KB");

		if (rs->unit_base == 1) {
			min *= 8.0;
			max *= 8.0;
			mean *= 8.0;
			dev *= 8.0;
		}

		if (rs->agg[ddir]) {
			p_of_agg = mean * 100 / (double) rs->agg[ddir];
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}

		if (mean > fkb_base * fkb_base) {
			min /= fkb_base;
			max /= fkb_base;
			mean /= fkb_base;
			dev /= fkb_base;
			bw_str = (rs->unit_base == 1 ? "Mbit" : "MB");
		}

		log_buf(out, "    bw (%-4s/s): min=%5lu, max=%5lu, per=%3.2f%%,"
			 " avg=%5.02f, stdev=%5.02f\n", bw_str, min, max,
							p_of_agg, mean, dev);
	}
}

static int show_lat(double *io_u_lat, int nr, const char **ranges,
		    const char *msg, struct buf_output *out)
{
	int new_line = 1, i, line = 0, shown = 0;

	for (i = 0; i < nr; i++) {
		if (io_u_lat[i] <= 0.0)
			continue;
		shown = 1;
		if (new_line) {
			if (line)
				log_buf(out, "\n");
			log_buf(out, "    lat (%s) : ", msg);
			new_line = 0;
			line = 0;
		}
		if (line)
			log_buf(out, ", ");
		log_buf(out, "%s%3.2f%%", ranges[i], io_u_lat[i]);
		line++;
		if (line == 5)
			new_line = 1;
	}

	if (shown)
		log_buf(out, "\n");

	return shown;
}

static void show_lat_u(double *io_u_lat_u, struct buf_output *out)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", };

	show_lat(io_u_lat_u, FIO_IO_U_LAT_U_NR, ranges, "usec", out);
}

static void show_lat_m(double *io_u_lat_m, struct buf_output *out)
{
	const char *ranges[] = { "2=", "4=", "10=", "20=", "50=", "100=",
				 "250=", "500=", "750=", "1000=", "2000=",
				 ">=2000=", };

	show_lat(io_u_lat_m, FIO_IO_U_LAT_M_NR, ranges, "msec", out);
}

static void show_latencies(struct thread_stat *ts, struct buf_output *out)
{
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];

	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

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
	uint32_t block1 = *(uint32_t *)bs1;
	uint32_t block2 = *(uint32_t *)bs2;
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
		qsort((void *)plist, len, sizeof(plist[0]), double_cmp);

	nr_uninit = 0;
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

static void show_thread_status_normal(struct thread_stat *ts,
				      struct group_run_stats *rs,
				      struct buf_output *out)
{
	double usr_cpu, sys_cpu;
	unsigned long runtime;
	double io_u_dist[FIO_IO_U_MAP_NR];
	time_t time_p;
	char time_buf[32];

	if (!ddir_rw_sum(ts->io_bytes) && !ddir_rw_sum(ts->total_io_u))
		return;

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

	if (ts->io_bytes[DDIR_READ])
		show_ddir_status(rs, ts, DDIR_READ, out);
	if (ts->io_bytes[DDIR_WRITE])
		show_ddir_status(rs, ts, DDIR_WRITE, out);
	if (ts->io_bytes[DDIR_TRIM])
		show_ddir_status(rs, ts, DDIR_TRIM, out);

	show_latencies(ts, out);

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
	log_buf(out, "     issued    : total=r=%llu/w=%llu/d=%llu,"
				 " short=r=%llu/w=%llu/d=%llu,"
				 " drop=r=%llu/w=%llu/d=%llu\n",
					(unsigned long long) ts->total_io_u[0],
					(unsigned long long) ts->total_io_u[1],
					(unsigned long long) ts->total_io_u[2],
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
}

static void show_ddir_status_terse(struct thread_stat *ts,
				   struct group_run_stats *rs, int ddir,
				   struct buf_output *out)
{
	unsigned long min, max;
	unsigned long long bw, iops;
	unsigned int *ovals = NULL;
	double mean, dev;
	unsigned int len, minv, maxv;
	int i;

	assert(ddir_rw(ddir));

	iops = bw = 0;
	if (ts->runtime[ddir]) {
		uint64_t runt = ts->runtime[ddir];

		bw = ((1000 * ts->io_bytes[ddir]) / runt) / 1024;
		iops = (1000 * (uint64_t) ts->total_io_u[ddir]) / runt;
	}

	log_buf(out, ";%llu;%llu;%llu;%llu",
		(unsigned long long) ts->io_bytes[ddir] >> 10, bw, iops,
					(unsigned long long) ts->runtime[ddir]);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_buf(out, ";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_buf(out, ";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (ts->clat_percentiles) {
		len = calc_clat_percentiles(ts->io_u_plat[ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list, &ovals, &maxv,
					&minv);
	} else
		len = 0;

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		if (i >= len) {
			log_buf(out, ";0%%=0");
			continue;
		}
		log_buf(out, ";%f%%=%u", ts->percentile_list[i].u.f, ovals[i]);
	}

	if (calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev))
		log_buf(out, ";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		log_buf(out, ";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (ovals)
		free(ovals);

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg = 100.0;

		if (rs->agg[ddir]) {
			p_of_agg = mean * 100 / (double) rs->agg[ddir];
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}

		log_buf(out, ";%lu;%lu;%f%%;%f;%f", min, max, p_of_agg, mean, dev);
	} else
		log_buf(out, ";%lu;%lu;%f%%;%f;%f", 0UL, 0UL, 0.0, 0.0, 0.0);
}

static void add_ddir_status_json(struct thread_stat *ts,
		struct group_run_stats *rs, int ddir, struct json_object *parent)
{
	unsigned long min, max;
	unsigned long long bw;
	unsigned int *ovals = NULL;
	double mean, dev, iops;
	unsigned int len, minv, maxv;
	int i;
	const char *ddirname[] = {"read", "write", "trim"};
	struct json_object *dir_object, *tmp_object, *percentile_object, *clat_bins_object;
	char buf[120];
	double p_of_agg = 100.0;

	assert(ddir_rw(ddir));

	if (ts->unified_rw_rep && ddir != DDIR_READ)
		return;

	dir_object = json_create_object();
	json_object_add_value_object(parent,
		ts->unified_rw_rep ? "mixed" : ddirname[ddir], dir_object);

	bw = 0;
	iops = 0.0;
	if (ts->runtime[ddir]) {
		uint64_t runt = ts->runtime[ddir];

		bw = ((1000 * ts->io_bytes[ddir]) / runt) / 1024;
		iops = (1000.0 * (uint64_t) ts->total_io_u[ddir]) / runt;
	}

	json_object_add_value_int(dir_object, "io_bytes", ts->io_bytes[ddir] >> 10);
	json_object_add_value_int(dir_object, "bw", bw);
	json_object_add_value_float(dir_object, "iops", iops);
	json_object_add_value_int(dir_object, "runtime", ts->runtime[ddir]);
	json_object_add_value_int(dir_object, "total_ios", ts->total_io_u[ddir]);
	json_object_add_value_int(dir_object, "short_ios", ts->short_io_u[ddir]);
	json_object_add_value_int(dir_object, "drop_ios", ts->drop_io_u[ddir]);

	if (!calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev)) {
		min = max = 0;
		mean = dev = 0.0;
	}
	tmp_object = json_create_object();
	json_object_add_value_object(dir_object, "slat", tmp_object);
	json_object_add_value_int(tmp_object, "min", min);
	json_object_add_value_int(tmp_object, "max", max);
	json_object_add_value_float(tmp_object, "mean", mean);
	json_object_add_value_float(tmp_object, "stddev", dev);

	if (!calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev)) {
		min = max = 0;
		mean = dev = 0.0;
	}
	tmp_object = json_create_object();
	json_object_add_value_object(dir_object, "clat", tmp_object);
	json_object_add_value_int(tmp_object, "min", min);
	json_object_add_value_int(tmp_object, "max", max);
	json_object_add_value_float(tmp_object, "mean", mean);
	json_object_add_value_float(tmp_object, "stddev", dev);

	if (ts->clat_percentiles) {
		len = calc_clat_percentiles(ts->io_u_plat[ddir],
					ts->clat_stat[ddir].samples,
					ts->percentile_list, &ovals, &maxv,
					&minv);
	} else
		len = 0;

	percentile_object = json_create_object();
	json_object_add_value_object(tmp_object, "percentile", percentile_object);
	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		if (i >= len) {
			json_object_add_value_int(percentile_object, "0.00", 0);
			continue;
		}
		snprintf(buf, sizeof(buf), "%f", ts->percentile_list[i].u.f);
		json_object_add_value_int(percentile_object, (const char *)buf, ovals[i]);
	}

	if (output_format & FIO_OUTPUT_JSON_PLUS) {
		clat_bins_object = json_create_object();
		json_object_add_value_object(tmp_object, "bins", clat_bins_object);
		for(i = 0; i < FIO_IO_U_PLAT_NR; i++) {
			snprintf(buf, sizeof(buf), "%d", i);
			json_object_add_value_int(clat_bins_object, (const char *)buf, ts->io_u_plat[ddir][i]);
		}
		json_object_add_value_int(clat_bins_object, "FIO_IO_U_PLAT_BITS", FIO_IO_U_PLAT_BITS);
		json_object_add_value_int(clat_bins_object, "FIO_IO_U_PLAT_VAL", FIO_IO_U_PLAT_VAL);
		json_object_add_value_int(clat_bins_object, "FIO_IO_U_PLAT_NR", FIO_IO_U_PLAT_NR);
	}

	if (!calc_lat(&ts->lat_stat[ddir], &min, &max, &mean, &dev)) {
		min = max = 0;
		mean = dev = 0.0;
	}
	tmp_object = json_create_object();
	json_object_add_value_object(dir_object, "lat", tmp_object);
	json_object_add_value_int(tmp_object, "min", min);
	json_object_add_value_int(tmp_object, "max", max);
	json_object_add_value_float(tmp_object, "mean", mean);
	json_object_add_value_float(tmp_object, "stddev", dev);
	if (ovals)
		free(ovals);

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		if (rs->agg[ddir]) {
			p_of_agg = mean * 100 / (double) rs->agg[ddir];
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}
	} else {
		min = max = 0;
		p_of_agg = mean = dev = 0.0;
	}
	json_object_add_value_int(dir_object, "bw_min", min);
	json_object_add_value_int(dir_object, "bw_max", max);
	json_object_add_value_float(dir_object, "bw_agg", p_of_agg);
	json_object_add_value_float(dir_object, "bw_mean", mean);
	json_object_add_value_float(dir_object, "bw_dev", dev);
}

static void show_thread_status_terse_v2(struct thread_stat *ts,
					struct group_run_stats *rs,
					struct buf_output *out)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;

	/* General Info */
	log_buf(out, "2;%s;%d;%d", ts->name, ts->groupid, ts->error);
	/* Log Read Status */
	show_ddir_status_terse(ts, rs, DDIR_READ, out);
	/* Log Write Status */
	show_ddir_status_terse(ts, rs, DDIR_WRITE, out);
	/* Log Trim Status */
	show_ddir_status_terse(ts, rs, DDIR_TRIM, out);

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
	stat_calc_lat_u(ts, io_u_lat_u);
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
	/* Additional output if continue_on_error set - default off*/
	if (ts->continue_on_error)
		log_buf(out, ";%llu;%d", (unsigned long long) ts->total_err_count, ts->first_error);
	log_buf(out, "\n");

	/* Additional output if description is set */
	if (strlen(ts->description))
		log_buf(out, ";%s", ts->description);

	log_buf(out, "\n");
}

static void show_thread_status_terse_v3_v4(struct thread_stat *ts,
					   struct group_run_stats *rs, int ver,
					   struct buf_output *out)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;

	/* General Info */
	log_buf(out, "%d;%s;%s;%d;%d", ver, fio_version_string,
					ts->name, ts->groupid, ts->error);
	/* Log Read Status */
	show_ddir_status_terse(ts, rs, DDIR_READ, out);
	/* Log Write Status */
	show_ddir_status_terse(ts, rs, DDIR_WRITE, out);
	/* Log Trim Status */
	if (ver == 4)
		show_ddir_status_terse(ts, rs, DDIR_TRIM, out);

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
	stat_calc_lat_u(ts, io_u_lat_u);
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
	show_disk_util(1, NULL, out);

	/* Additional output if continue_on_error set - default off*/
	if (ts->continue_on_error)
		log_buf(out, ";%llu;%d", (unsigned long long) ts->total_err_count, ts->first_error);

	/* Additional output if description is set */
	if (strlen(ts->description))
		log_buf(out, ";%s", ts->description);

	log_buf(out, "\n");
}

void json_add_job_opts(struct json_object *root, const char *name,
		       struct flist_head *opt_list, bool num_jobs)
{
	struct json_object *dir_object;
	struct flist_head *entry;
	struct print_option *p;

	if (flist_empty(opt_list))
		return;

	dir_object = json_create_object();
	json_object_add_value_object(root, name, dir_object);

	flist_for_each(entry, opt_list) {
		const char *pos = "";

		p = flist_entry(entry, struct print_option, list);
		if (!num_jobs && !strcmp(p->name, "numjobs"))
			continue;
		if (p->value)
			pos = p->value;
		json_object_add_value_string(dir_object, p->name, pos);
	}
}

static struct json_object *show_thread_status_json(struct thread_stat *ts,
						   struct group_run_stats *rs,
						   struct flist_head *opt_list)
{
	struct json_object *root, *tmp;
	struct jobs_eta *je;
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	double usr_cpu, sys_cpu;
	int i;
	size_t size;

	root = json_create_object();
	json_object_add_value_string(root, "jobname", ts->name);
	json_object_add_value_int(root, "groupid", ts->groupid);
	json_object_add_value_int(root, "error", ts->error);

	/* ETA Info */
	je = get_jobs_eta(true, &size);
	if (je) {
		json_object_add_value_int(root, "eta", je->eta_sec);
		json_object_add_value_int(root, "elapsed", je->elapsed_sec);
	}

	if (opt_list)
		json_add_job_opts(root, "job options", opt_list, true);

	add_ddir_status_json(ts, rs, DDIR_READ, root);
	add_ddir_status_json(ts, rs, DDIR_WRITE, root);
	add_ddir_status_json(ts, rs, DDIR_TRIM, root);

	/* CPU Usage */
	if (ts->total_run_time) {
		double runt = (double) ts->total_run_time;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}
	json_object_add_value_float(root, "usr_cpu", usr_cpu);
	json_object_add_value_float(root, "sys_cpu", sys_cpu);
	json_object_add_value_int(root, "ctx", ts->ctx);
	json_object_add_value_int(root, "majf", ts->majf);
	json_object_add_value_int(root, "minf", ts->minf);


	/* Calc % distribution of IO depths, usecond, msecond latency */
	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);
	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

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

	tmp = json_create_object();
	json_object_add_value_object(root, "latency_us", tmp);
	/* Microsecond latency */
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
							  (const char *)buf,
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

	return root;
}

static void show_thread_status_terse(struct thread_stat *ts,
				     struct group_run_stats *rs,
				     struct buf_output *out)
{
	if (terse_version == 2)
		show_thread_status_terse_v2(ts, rs, out);
	else if (terse_version == 3 || terse_version == 4)
		show_thread_status_terse_v3_v4(ts, rs, terse_version, out);
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

static void sum_stat(struct io_stat *dst, struct io_stat *src, bool first)
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

void sum_group_stats(struct group_run_stats *dst, struct group_run_stats *src)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (dst->max_run[i] < src->max_run[i])
			dst->max_run[i] = src->max_run[i];
		if (dst->min_run[i] && dst->min_run[i] > src->min_run[i])
			dst->min_run[i] = src->min_run[i];
		if (dst->max_bw[i] < src->max_bw[i])
			dst->max_bw[i] = src->max_bw[i];
		if (dst->min_bw[i] && dst->min_bw[i] > src->min_bw[i])
			dst->min_bw[i] = src->min_bw[i];

		dst->io_kb[i] += src->io_kb[i];
		dst->agg[i] += src->agg[i];
	}

	if (!dst->kb_base)
		dst->kb_base = src->kb_base;
	if (!dst->unit_base)
		dst->unit_base = src->unit_base;
}

void sum_thread_stats(struct thread_stat *dst, struct thread_stat *src,
		      bool first)
{
	int l, k;

	for (l = 0; l < DDIR_RWDIR_CNT; l++) {
		if (!dst->unified_rw_rep) {
			sum_stat(&dst->clat_stat[l], &src->clat_stat[l], first);
			sum_stat(&dst->slat_stat[l], &src->slat_stat[l], first);
			sum_stat(&dst->lat_stat[l], &src->lat_stat[l], first);
			sum_stat(&dst->bw_stat[l], &src->bw_stat[l], first);

			dst->io_bytes[l] += src->io_bytes[l];

			if (dst->runtime[l] < src->runtime[l])
				dst->runtime[l] = src->runtime[l];
		} else {
			sum_stat(&dst->clat_stat[0], &src->clat_stat[l], first);
			sum_stat(&dst->slat_stat[0], &src->slat_stat[l], first);
			sum_stat(&dst->lat_stat[0], &src->lat_stat[l], first);
			sum_stat(&dst->bw_stat[0], &src->bw_stat[l], first);

			dst->io_bytes[0] += src->io_bytes[l];

			if (dst->runtime[0] < src->runtime[l])
				dst->runtime[0] = src->runtime[l];

			/*
			 * We're summing to the same destination, so override
			 * 'first' after the first iteration of the loop
			 */
			first = false;
		}
	}

	dst->usr_time += src->usr_time;
	dst->sys_time += src->sys_time;
	dst->ctx += src->ctx;
	dst->majf += src->majf;
	dst->minf += src->minf;

	for (k = 0; k < FIO_IO_U_MAP_NR; k++)
		dst->io_u_map[k] += src->io_u_map[k];
	for (k = 0; k < FIO_IO_U_MAP_NR; k++)
		dst->io_u_submit[k] += src->io_u_submit[k];
	for (k = 0; k < FIO_IO_U_MAP_NR; k++)
		dst->io_u_complete[k] += src->io_u_complete[k];
	for (k = 0; k < FIO_IO_U_LAT_U_NR; k++)
		dst->io_u_lat_u[k] += src->io_u_lat_u[k];
	for (k = 0; k < FIO_IO_U_LAT_M_NR; k++)
		dst->io_u_lat_m[k] += src->io_u_lat_m[k];

	for (k = 0; k < DDIR_RWDIR_CNT; k++) {
		if (!dst->unified_rw_rep) {
			dst->total_io_u[k] += src->total_io_u[k];
			dst->short_io_u[k] += src->short_io_u[k];
			dst->drop_io_u[k] += src->drop_io_u[k];
		} else {
			dst->total_io_u[0] += src->total_io_u[k];
			dst->short_io_u[0] += src->short_io_u[k];
			dst->drop_io_u[0] += src->drop_io_u[k];
		}
	}

	for (k = 0; k < DDIR_RWDIR_CNT; k++) {
		int m;

		for (m = 0; m < FIO_IO_U_PLAT_NR; m++) {
			if (!dst->unified_rw_rep)
				dst->io_u_plat[k][m] += src->io_u_plat[k][m];
			else
				dst->io_u_plat[0][m] += src->io_u_plat[k][m];
		}
	}

	dst->total_run_time += src->total_run_time;
	dst->total_submit += src->total_submit;
	dst->total_complete += src->total_complete;
}

void init_group_run_stat(struct group_run_stats *gs)
{
	int i;
	memset(gs, 0, sizeof(*gs));

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		gs->min_bw[i] = gs->min_run[i] = ~0UL;
}

void init_thread_stat(struct thread_stat *ts)
{
	int j;

	memset(ts, 0, sizeof(*ts));

	for (j = 0; j < DDIR_RWDIR_CNT; j++) {
		ts->lat_stat[j].min_val = -1UL;
		ts->clat_stat[j].min_val = -1UL;
		ts->slat_stat[j].min_val = -1UL;
		ts->bw_stat[j].min_val = -1UL;
	}
	ts->groupid = -1;
}

void __show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	struct thread_stat *threadstats, *ts;
	int i, j, k, nr_ts, last_ts, idx;
	int kb_base_warned = 0;
	int unit_base_warned = 0;
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
	opt_lists = malloc(nr_ts * sizeof(struct flist_head *));

	for (i = 0; i < nr_ts; i++) {
		init_thread_stat(&threadstats[i]);
		opt_lists[i] = NULL;
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
		ts->percentile_precision = td->o.percentile_precision;
		memcpy(ts->percentile_list, td->o.percentile_list, sizeof(td->o.percentile_list));
		opt_lists[j] = &td->opt_list;

		idx++;
		ts->members++;

		if (ts->groupid == -1) {
			/*
			 * These are per-group shared already
			 */
			strncpy(ts->name, td->o.name, FIO_JOBNAME_SIZE - 1);
			if (td->o.description)
				strncpy(ts->description, td->o.description,
						FIO_JOBDESC_SIZE - 1);
			else
				memset(ts->description, 0, FIO_JOBDESC_SIZE);

			/*
			 * If multiple entries in this group, this is
			 * the first member.
			 */
			ts->thread_number = td->thread_number;
			ts->groupid = td->groupid;

			/*
			 * first pid in group, not very useful...
			 */
			ts->pid = td->pid;

			ts->kb_base = td->o.kb_base;
			ts->unit_base = td->o.unit_base;
			ts->unified_rw_rep = td->o.unified_rw_rep;
		} else if (ts->kb_base != td->o.kb_base && !kb_base_warned) {
			log_info("fio: kb_base differs for jobs in group, using"
				 " %u as the base\n", ts->kb_base);
			kb_base_warned = 1;
		} else if (ts->unit_base != td->o.unit_base && !unit_base_warned) {
			log_info("fio: unit_base differs for jobs in group, using"
				 " %u as the base\n", ts->unit_base);
			unit_base_warned = 1;
		}

		ts->continue_on_error = td->o.continue_on_error;
		ts->total_err_count += td->total_err_count;
		ts->first_error = td->first_error;
		if (!ts->error) {
			if (!td->error && td->o.continue_on_error &&
			    td->first_error) {
				ts->error = td->first_error;
				ts->verror[sizeof(ts->verror) - 1] = '\0';
				strncpy(ts->verror, td->verror, sizeof(ts->verror) - 1);
			} else  if (td->error) {
				ts->error = td->error;
				ts->verror[sizeof(ts->verror) - 1] = '\0';
				strncpy(ts->verror, td->verror, sizeof(ts->verror) - 1);
			}
		}

		ts->latency_depth = td->latency_qd;
		ts->latency_target = td->o.latency_target;
		ts->latency_percentile = td->o.latency_percentile;
		ts->latency_window = td->o.latency_window;

		ts->nr_block_infos = td->ts.nr_block_infos;
		for (k = 0; k < ts->nr_block_infos; k++)
			ts->block_infos[k] = td->ts.block_infos[k];

		sum_thread_stats(ts, &td->ts, idx == 1);
	}

	for (i = 0; i < nr_ts; i++) {
		unsigned long long bw;

		ts = &threadstats[i];
		if (ts->groupid == -1)
			continue;
		rs = &runstats[ts->groupid];
		rs->kb_base = ts->kb_base;
		rs->unit_base = ts->unit_base;
		rs->unified_rw_rep += ts->unified_rw_rep;

		for (j = 0; j < DDIR_RWDIR_CNT; j++) {
			if (!ts->runtime[j])
				continue;
			if (ts->runtime[j] < rs->min_run[j] || !rs->min_run[j])
				rs->min_run[j] = ts->runtime[j];
			if (ts->runtime[j] > rs->max_run[j])
				rs->max_run[j] = ts->runtime[j];

			bw = 0;
			if (ts->runtime[j]) {
				unsigned long runt = ts->runtime[j];
				unsigned long long kb;

				kb = ts->io_bytes[j] / rs->kb_base;
				bw = kb * 1000 / runt;
			}
			if (bw < rs->min_bw[j])
				rs->min_bw[j] = bw;
			if (bw > rs->max_bw[j])
				rs->max_bw[j] = bw;

			rs->io_kb[j] += ts->io_bytes[j] / rs->kb_base;
		}
	}

	for (i = 0; i < groupid + 1; i++) {
		int ddir;

		rs = &runstats[i];

		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			if (rs->max_run[ddir])
				rs->agg[ddir] = (rs->io_kb[ddir] * 1000) /
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
		time_t time_p;

		time(&time_p);
		os_ctime_r((const time_t *) &time_p, time_buf,
				sizeof(time_buf));
		time_buf[strlen(time_buf) - 1] = '\0';

		root = json_create_object();
		json_object_add_value_string(root, "fio version", fio_version_string);
		json_object_add_value_int(root, "timestamp", time_p);
		json_object_add_value_string(root, "time", time_buf);
		global = get_global_options();
		json_add_job_opts(root, "global options", &global->opt_list, false);
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
		buf_output_flush(&output[i]);
		buf_output_free(&output[i]);
	}

	log_info_flush();
	free(runstats);
	free(threadstats);
	free(opt_lists);
}

void show_run_stats(void)
{
	fio_mutex_down(stat_mutex);
	__show_run_stats();
	fio_mutex_up(stat_mutex);
}

void __show_running_run_stats(void)
{
	struct thread_data *td;
	unsigned long long *rt;
	struct timeval tv;
	int i;

	fio_mutex_down(stat_mutex);

	rt = malloc(thread_number * sizeof(unsigned long long));
	fio_gettime(&tv, NULL);

	for_each_td(td, i) {
		td->update_rusage = 1;
		td->ts.io_bytes[DDIR_READ] = td->io_bytes[DDIR_READ];
		td->ts.io_bytes[DDIR_WRITE] = td->io_bytes[DDIR_WRITE];
		td->ts.io_bytes[DDIR_TRIM] = td->io_bytes[DDIR_TRIM];
		td->ts.total_run_time = mtime_since(&td->epoch, &tv);

		rt[i] = mtime_since(&td->start, &tv);
		if (td_read(td) && td->ts.io_bytes[DDIR_READ])
			td->ts.runtime[DDIR_READ] += rt[i];
		if (td_write(td) && td->ts.io_bytes[DDIR_WRITE])
			td->ts.runtime[DDIR_WRITE] += rt[i];
		if (td_trim(td) && td->ts.io_bytes[DDIR_TRIM])
			td->ts.runtime[DDIR_TRIM] += rt[i];
	}

	for_each_td(td, i) {
		if (td->runstate >= TD_EXITED)
			continue;
		if (td->rusage_sem) {
			td->update_rusage = 1;
			fio_mutex_down(td->rusage_sem);
		}
		td->update_rusage = 0;
	}

	__show_run_stats();

	for_each_td(td, i) {
		if (td_read(td) && td->ts.io_bytes[DDIR_READ])
			td->ts.runtime[DDIR_READ] -= rt[i];
		if (td_write(td) && td->ts.io_bytes[DDIR_WRITE])
			td->ts.runtime[DDIR_WRITE] -= rt[i];
		if (td_trim(td) && td->ts.io_bytes[DDIR_TRIM])
			td->ts.runtime[DDIR_TRIM] -= rt[i];
	}

	free(rt);
	fio_mutex_up(stat_mutex);
}

static int status_interval_init;
static struct timeval status_time;
static int status_file_disabled;

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

	snprintf(fio_status_file_path, sizeof(fio_status_file_path), "%s/%s", temp_dir, FIO_STATUS_FILE);

	if (stat(fio_status_file_path, &sb))
		return 0;

	if (unlink(fio_status_file_path) < 0) {
		log_err("fio: failed to unlink %s: %s\n", fio_status_file_path,
							strerror(errno));
		log_err("fio: disabling status file updates\n");
		status_file_disabled = 1;
	}

	return 1;
}

void check_for_running_stats(void)
{
	if (status_interval) {
		if (!status_interval_init) {
			fio_gettime(&status_time, NULL);
			status_interval_init = 1;
		} else if (mtime_since_now(&status_time) >= status_interval) {
			show_running_run_stats();
			fio_gettime(&status_time, NULL);
			return;
		}
	}
	if (check_status_file()) {
		show_running_run_stats();
		return;
	}
}

static inline void add_stat_sample(struct io_stat *is, unsigned long data)
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

static void __add_log_sample(struct io_log *iolog, unsigned long val,
			     enum fio_ddir ddir, unsigned int bs,
			     unsigned long t, uint64_t offset)
{
	uint64_t nr_samples = iolog->nr_samples;
	struct io_sample *s;

	if (iolog->disabled)
		return;

	if (!iolog->nr_samples)
		iolog->avg_last = t;

	if (iolog->nr_samples == iolog->max_samples) {
		size_t new_size, new_samples;
		void *new_log;

		if (!iolog->max_samples)
			new_samples = DEF_LOG_ENTRIES;
		else
			new_samples = iolog->max_samples * 2;

		new_size = new_samples * log_entry_sz(iolog);

		if (iolog->log_gz && (new_size > iolog->log_gz)) {
			if (!iolog->log) {
				iolog->log = malloc(new_size);
				iolog->max_samples = new_samples;
			} else if (iolog_flush(iolog, 0)) {
				log_err("fio: failed flushing iolog! Will stop logging.\n");
				iolog->disabled = 1;
				return;
			}
			nr_samples = iolog->nr_samples;
		} else {
			new_log = realloc(iolog->log, new_size);
			if (!new_log) {
				log_err("fio: failed extending iolog! Will stop logging.\n");
				iolog->disabled = 1;
				return;
			}
			iolog->log = new_log;
			iolog->max_samples = new_samples;
		}
	}

	s = get_sample(iolog, nr_samples);

	s->val = val;
	s->time = t;
	io_sample_set_ddir(iolog, s, ddir);
	s->bs = bs;

	if (iolog->log_offset) {
		struct io_sample_offset *so = (void *) s;

		so->offset = offset;
	}

	iolog->nr_samples++;
}

static inline void reset_io_stat(struct io_stat *ios)
{
	ios->max_val = ios->min_val = ios->samples = 0;
	ios->mean.u.f = ios->S.u.f = 0;
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

		for (j = 0; j < FIO_IO_U_PLAT_NR; j++)
			ts->io_u_plat[i][j] = 0;
	}

	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		ts->io_u_map[i] = 0;
		ts->io_u_submit[i] = 0;
		ts->io_u_complete[i] = 0;
		ts->io_u_lat_u[i] = 0;
		ts->io_u_lat_m[i] = 0;
		ts->total_submit = 0;
		ts->total_complete = 0;
	}

	for (i = 0; i < 3; i++) {
		ts->total_io_u[i] = 0;
		ts->short_io_u[i] = 0;
		ts->drop_io_u[i] = 0;
	}
}

static void __add_stat_to_log(struct io_log *iolog, enum fio_ddir ddir,
			      unsigned long elapsed, bool log_max)
{
	/*
	 * Note an entry in the log. Use the mean from the logged samples,
	 * making sure to properly round up. Only write a log entry if we
	 * had actual samples done.
	 */
	if (iolog->avg_window[ddir].samples) {
		unsigned long val;

		if (log_max)
			val = iolog->avg_window[ddir].max_val;
		else
			val = iolog->avg_window[ddir].mean.u.f + 0.50;

		__add_log_sample(iolog, val, ddir, 0, elapsed, 0);
	}

	reset_io_stat(&iolog->avg_window[ddir]);
}

static void _add_stat_to_log(struct io_log *iolog, unsigned long elapsed,
			     bool log_max)
{
	int ddir;

	for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++)
		__add_stat_to_log(iolog, ddir, elapsed, log_max);
}

static void add_log_sample(struct thread_data *td, struct io_log *iolog,
			   unsigned long val, enum fio_ddir ddir,
			   unsigned int bs, uint64_t offset)
{
	unsigned long elapsed, this_window;

	if (!ddir_rw(ddir))
		return;

	elapsed = mtime_since_now(&td->epoch);

	/*
	 * If no time averaging, just add the log sample.
	 */
	if (!iolog->avg_msec) {
		__add_log_sample(iolog, val, ddir, bs, elapsed, offset);
		return;
	}

	/*
	 * Add the sample. If the time period has passed, then
	 * add that entry to the log and clear.
	 */
	add_stat_sample(&iolog->avg_window[ddir], val);

	/*
	 * If period hasn't passed, adding the above sample is all we
	 * need to do.
	 */
	this_window = elapsed - iolog->avg_last;
	if (this_window < iolog->avg_msec)
		return;

	_add_stat_to_log(iolog, elapsed, td->o.log_max != 0);

	iolog->avg_last = elapsed;
}

void finalize_logs(struct thread_data *td, bool unit_logs)
{
	unsigned long elapsed;

	elapsed = mtime_since_now(&td->epoch);

	if (td->clat_log && unit_logs)
		_add_stat_to_log(td->clat_log, elapsed, td->o.log_max != 0);
	if (td->slat_log && unit_logs)
		_add_stat_to_log(td->slat_log, elapsed, td->o.log_max != 0);
	if (td->lat_log && unit_logs)
		_add_stat_to_log(td->lat_log, elapsed, td->o.log_max != 0);
	if (td->bw_log && (unit_logs == per_unit_log(td->bw_log)))
		_add_stat_to_log(td->bw_log, elapsed, td->o.log_max != 0);
	if (td->iops_log && (unit_logs == per_unit_log(td->iops_log)))
		_add_stat_to_log(td->iops_log, elapsed, td->o.log_max != 0);
}

void add_agg_sample(unsigned long val, enum fio_ddir ddir, unsigned int bs)
{
	struct io_log *iolog;

	if (!ddir_rw(ddir))
		return;

	iolog = agg_io_log[ddir];
	__add_log_sample(iolog, val, ddir, bs, mtime_since_genesis(), 0);
}

static void add_clat_percentile_sample(struct thread_stat *ts,
				unsigned long usec, enum fio_ddir ddir)
{
	unsigned int idx = plat_val_to_idx(usec);
	assert(idx < FIO_IO_U_PLAT_NR);

	ts->io_u_plat[ddir][idx]++;
}

void add_clat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec, unsigned int bs, uint64_t offset)
{
	struct thread_stat *ts = &td->ts;

	td_io_u_lock(td);

	add_stat_sample(&ts->clat_stat[ddir], usec);

	if (td->clat_log)
		add_log_sample(td, td->clat_log, usec, ddir, bs, offset);

	if (ts->clat_percentiles)
		add_clat_percentile_sample(ts, usec, ddir);

	td_io_u_unlock(td);
}

void add_slat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long usec, unsigned int bs, uint64_t offset)
{
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	td_io_u_lock(td);

	add_stat_sample(&ts->slat_stat[ddir], usec);

	if (td->slat_log)
		add_log_sample(td, td->slat_log, usec, ddir, bs, offset);

	td_io_u_unlock(td);
}

void add_lat_sample(struct thread_data *td, enum fio_ddir ddir,
		    unsigned long usec, unsigned int bs, uint64_t offset)
{
	struct thread_stat *ts = &td->ts;

	if (!ddir_rw(ddir))
		return;

	td_io_u_lock(td);

	add_stat_sample(&ts->lat_stat[ddir], usec);

	if (td->lat_log)
		add_log_sample(td, td->lat_log, usec, ddir, bs, offset);

	td_io_u_unlock(td);
}

void add_bw_sample(struct thread_data *td, struct io_u *io_u,
		   unsigned int bytes, unsigned long spent)
{
	struct thread_stat *ts = &td->ts;
	unsigned long rate;

	if (spent)
		rate = bytes * 1000 / spent;
	else
		rate = 0;

	td_io_u_lock(td);

	add_stat_sample(&ts->bw_stat[io_u->ddir], rate);

	if (td->bw_log)
		add_log_sample(td, td->bw_log, rate, io_u->ddir, bytes, io_u->offset);

	td->stat_io_bytes[io_u->ddir] = td->this_io_bytes[io_u->ddir];
	td_io_u_unlock(td);
}

static int add_bw_samples(struct thread_data *td, struct timeval *t)
{
	struct thread_stat *ts = &td->ts;
	unsigned long spent, rate;
	enum fio_ddir ddir;

	if (per_unit_log(td->bw_log))
		return 0;

	spent = mtime_since(&td->bw_sample_time, t);
	if (spent < td->o.bw_avg_time &&
	    td->o.bw_avg_time - spent >= 10)
		return td->o.bw_avg_time - spent;

	td_io_u_lock(td);

	/*
	 * Compute both read and write rates for the interval.
	 */
	for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
		uint64_t delta;

		delta = td->this_io_bytes[ddir] - td->stat_io_bytes[ddir];
		if (!delta)
			continue; /* No entries for interval */

		if (spent)
			rate = delta * 1000 / spent / 1024;
		else
			rate = 0;

		add_stat_sample(&ts->bw_stat[ddir], rate);

		if (td->bw_log) {
			unsigned int bs = 0;

			if (td->o.min_bs[ddir] == td->o.max_bs[ddir])
				bs = td->o.min_bs[ddir];

			add_log_sample(td, td->bw_log, rate, ddir, bs, 0);
		}

		td->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
	}

	timeval_add_msec(&td->bw_sample_time, td->o.bw_avg_time);

	td_io_u_unlock(td);

	if (spent <= td->o.bw_avg_time)
		return td->o.bw_avg_time;

	return td->o.bw_avg_time - (1 + spent - td->o.bw_avg_time);
}

void add_iops_sample(struct thread_data *td, struct io_u *io_u,
		     unsigned int bytes)
{
	struct thread_stat *ts = &td->ts;

	td_io_u_lock(td);

	add_stat_sample(&ts->iops_stat[io_u->ddir], 1);

	if (td->iops_log)
		add_log_sample(td, td->iops_log, 1, io_u->ddir, bytes, io_u->offset);

	td->stat_io_blocks[io_u->ddir] = td->this_io_blocks[io_u->ddir];
	td_io_u_unlock(td);
}

static int add_iops_samples(struct thread_data *td, struct timeval *t)
{
	struct thread_stat *ts = &td->ts;
	unsigned long spent, iops;
	enum fio_ddir ddir;

	if (per_unit_log(td->iops_log))
		return 0;

	spent = mtime_since(&td->iops_sample_time, t);
	if (spent < td->o.iops_avg_time &&
	    td->o.iops_avg_time - spent >= 10)
		return td->o.iops_avg_time - spent;

	td_io_u_lock(td);

	/*
	 * Compute both read and write rates for the interval.
	 */
	for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
		uint64_t delta;

		delta = td->this_io_blocks[ddir] - td->stat_io_blocks[ddir];
		if (!delta)
			continue; /* No entries for interval */

		if (spent)
			iops = (delta * 1000) / spent;
		else
			iops = 0;

		add_stat_sample(&ts->iops_stat[ddir], iops);

		if (td->iops_log) {
			unsigned int bs = 0;

			if (td->o.min_bs[ddir] == td->o.max_bs[ddir])
				bs = td->o.min_bs[ddir];

			add_log_sample(td, td->iops_log, iops, ddir, bs, 0);
		}

		td->stat_io_blocks[ddir] = td->this_io_blocks[ddir];
	}

	timeval_add_msec(&td->iops_sample_time, td->o.iops_avg_time);

	td_io_u_unlock(td);

	if (spent <= td->o.iops_avg_time)
		return td->o.iops_avg_time;

	return td->o.iops_avg_time - (1 + spent - td->o.iops_avg_time);
}

/*
 * Returns msecs to next event
 */
int calc_log_samples(void)
{
	struct thread_data *td;
	unsigned int next = ~0U, tmp;
	struct timeval now;
	int i;

	fio_gettime(&now, NULL);

	for_each_td(td, i) {
		if (!ramp_time_over(td) ||
		    !(td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING)) {
			next = min(td->o.iops_avg_time, td->o.bw_avg_time);
			continue;
		}
		if (!per_unit_log(td->bw_log)) {
			tmp = add_bw_samples(td, &now);
			if (tmp < next)
				next = tmp;
		}
		if (!per_unit_log(td->iops_log)) {
			tmp = add_iops_samples(td, &now);
			if (tmp < next)
				next = tmp;
		}
	}

	return next == ~0U ? 0 : next;
}

void stat_init(void)
{
	stat_mutex = fio_mutex_init(FIO_MUTEX_UNLOCKED);
}

void stat_exit(void)
{
	/*
	 * When we have the mutex, we know out-of-band access to it
	 * have ended.
	 */
	fio_mutex_down(stat_mutex);
	fio_mutex_remove(stat_mutex);
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
