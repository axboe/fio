#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <math.h>

#include "fio.h"

static struct itimerval itimer;
static struct list_head disk_list = LIST_HEAD_INIT(disk_list);
static dev_t last_dev;

/*
 * Cheesy number->string conversion, complete with carry rounding error.
 */
static char *num2str(unsigned long num, int maxlen, int base)
{
	/*
	 * could be passed in for 10^3 base, but every caller expects
	 * 2^10 base right now.
	 */
	const unsigned int thousand = 1024;
	char postfix[] = { 'K', 'M', 'G', 'P', 'E' };
	char *buf;
	int i;

	buf = malloc(128);

	for (i = 0; base > 1; i++)
		base /= thousand;

	do {
		int len, carry = 0;

		len = sprintf(buf, "%'lu", num);
		if (len <= maxlen) {
			buf[len] = postfix[i];
			buf[len + 1] = '\0';
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

static int get_io_ticks(struct disk_util *du, struct disk_util_stat *dus)
{
	unsigned in_flight;
	char line[256];
	FILE *f;
	char *p;

	f = fopen(du->path, "r");
	if (!f)
		return 1;

	p = fgets(line, sizeof(line), f);
	if (!p) {
		fclose(f);
		return 1;
	}

	if (sscanf(p, "%u %u %llu %u %u %u %llu %u %u %u %u\n", &dus->ios[0], &dus->merges[0], &dus->sectors[0], &dus->ticks[0], &dus->ios[1], &dus->merges[1], &dus->sectors[1], &dus->ticks[1], &in_flight, &dus->io_ticks, &dus->time_in_queue) != 11) {
		fclose(f);
		return 1;
	}

	fclose(f);
	return 0;
}

static void update_io_tick_disk(struct disk_util *du)
{
	struct disk_util_stat __dus, *dus, *ldus;
	struct timeval t;

	if (get_io_ticks(du, &__dus))
		return;

	dus = &du->dus;
	ldus = &du->last_dus;

	dus->sectors[0] += (__dus.sectors[0] - ldus->sectors[0]);
	dus->sectors[1] += (__dus.sectors[1] - ldus->sectors[1]);
	dus->ios[0] += (__dus.ios[0] - ldus->ios[0]);
	dus->ios[1] += (__dus.ios[1] - ldus->ios[1]);
	dus->merges[0] += (__dus.merges[0] - ldus->merges[0]);
	dus->merges[1] += (__dus.merges[1] - ldus->merges[1]);
	dus->ticks[0] += (__dus.ticks[0] - ldus->ticks[0]);
	dus->ticks[1] += (__dus.ticks[1] - ldus->ticks[1]);
	dus->io_ticks += (__dus.io_ticks - ldus->io_ticks);
	dus->time_in_queue += (__dus.time_in_queue - ldus->time_in_queue);

	fio_gettime(&t, NULL);
	du->msec += mtime_since(&du->time, &t);
	memcpy(&du->time, &t, sizeof(t));
	memcpy(ldus, &__dus, sizeof(__dus));
}

void update_io_ticks(void)
{
	struct list_head *entry;
	struct disk_util *du;

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);
		update_io_tick_disk(du);
	}
}

static int disk_util_exists(dev_t dev)
{
	struct list_head *entry;
	struct disk_util *du;

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);

		if (du->dev == dev)
			return 1;
	}

	return 0;
}

static void disk_util_add(dev_t dev, char *path)
{
	struct disk_util *du, *__du;
	struct list_head *entry;

	du = malloc(sizeof(*du));
	memset(du, 0, sizeof(*du));
	INIT_LIST_HEAD(&du->list);
	sprintf(du->path, "%s/stat", path);
	du->name = strdup(basename(path));
	du->dev = dev;

	list_for_each(entry, &disk_list) {
		__du = list_entry(entry, struct disk_util, list);

		if (!strcmp(du->name, __du->name)) {
			free(du->name);
			free(du);
			return;
		}
	}

	fio_gettime(&du->time, NULL);
	get_io_ticks(du, &du->last_dus);

	list_add_tail(&du->list, &disk_list);
}

static int check_dev_match(dev_t dev, char *path)
{
	unsigned int major, minor;
	char line[256], *p;
	FILE *f;

	f = fopen(path, "r");
	if (!f) {
		perror("open path");
		return 1;
	}

	p = fgets(line, sizeof(line), f);
	if (!p) {
		fclose(f);
		return 1;
	}

	if (sscanf(p, "%u:%u", &major, &minor) != 2) {
		fclose(f);
		return 1;
	}

	if (((major << 8) | minor) == dev) {
		fclose(f);
		return 0;
	}

	fclose(f);
	return 1;
}

static int find_block_dir(dev_t dev, char *path)
{
	struct dirent *dir;
	struct stat st;
	int found = 0;
	DIR *D;

	D = opendir(path);
	if (!D)
		return 0;

	while ((dir = readdir(D)) != NULL) {
		char full_path[256];

		if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, ".."))
			continue;

		sprintf(full_path, "%s/%s", path, dir->d_name);

		if (!strcmp(dir->d_name, "dev")) {
			if (!check_dev_match(dev, full_path)) {
				found = 1;
				break;
			}
		}

		if (lstat(full_path, &st) == -1) {
			perror("stat");
			break;
		}

		if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
			continue;

		found = find_block_dir(dev, full_path);
		if (found) {
			strcpy(path, full_path);
			break;
		}
	}

	closedir(D);
	return found;
}

void init_disk_util(struct thread_data *td)
{
	struct fio_file *f;
	struct stat st;
	char foo[PATH_MAX], tmp[PATH_MAX];
	dev_t dev;
	char *p;

	if (!td->do_disk_util || (td->io_ops->flags & FIO_DISKLESSIO))
		return;

	/*
	 * Just use the same file, they are on the same device.
	 */
	f = &td->files[0];
	if (!stat(f->file_name, &st)) {
		if (S_ISBLK(st.st_mode))
			dev = st.st_rdev;
		else
			dev = st.st_dev;
	} else {
		/*
		 * must be a file, open "." in that path
		 */
		strncpy(foo, f->file_name, PATH_MAX - 1);
		p = dirname(foo);
		if (stat(p, &st)) {
			perror("disk util stat");
			return;
		}

		dev = st.st_dev;
	}

	if (disk_util_exists(dev))
		return;

	/*
	 * for an fs without a device, we will repeatedly stat through
	 * sysfs which can take oodles of time for thousands of files. so
	 * cache the last lookup and compare with that before going through
	 * everything again.
	 */
	if (dev == last_dev)
		return;

	last_dev = dev;
		
	sprintf(foo, "/sys/block");
	if (!find_block_dir(dev, foo))
		return;

	/*
	 * If there's a ../queue/ directory there, we are inside a partition.
	 * Check if that is the case and jump back. For loop/md/dm etc we
	 * are already in the right spot.
	 */
	sprintf(tmp, "%s/../queue", foo);
	if (!stat(tmp, &st)) {
		p = dirname(foo);
		sprintf(tmp, "%s/queue", p);
		if (stat(tmp, &st)) {
			log_err("unknown sysfs layout\n");
			return;
		}
		strncpy(tmp, p, PATH_MAX - 1);
		sprintf(foo, "%s", tmp);
	}

	if (td->ioscheduler)
		td->sysfs_root = strdup(foo);

	disk_util_add(dev, foo);
}

void disk_util_timer_arm(void)
{
	itimer.it_value.tv_sec = 0;
	itimer.it_value.tv_usec = DISK_UTIL_MSEC * 1000;
	setitimer(ITIMER_REAL, &itimer, NULL);
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

	fprintf(f_out, "\nRun status group %d (all jobs):\n", id);

	for (i = 0; i <= DDIR_WRITE; i++) {
		if (!rs->max_run[i])
			continue;

		p1 = num2str(rs->io_kb[i], 6, 1);
		p2 = num2str(rs->agg[i], 6, 1);
		p3 = num2str(rs->min_bw[i], 6, 1);
		p4 = num2str(rs->max_bw[i], 6, 1);

		fprintf(f_out, "%s: io=%siB, aggrb=%siB/s, minb=%siB/s, maxb=%siB/s, mint=%llumsec, maxt=%llumsec\n", ddir_str[i], p1, p2, p3, p4, rs->min_run[0], rs->max_run[0]);

		free(p1);
		free(p2);
		free(p3);
		free(p4);
	}
}

static void show_disk_util(void)
{
	struct disk_util_stat *dus;
	struct list_head *entry, *next;
	struct disk_util *du;
	double util;

	fprintf(f_out, "\nDisk stats (read/write):\n");

	list_for_each(entry, &disk_list) {
		du = list_entry(entry, struct disk_util, list);
		dus = &du->dus;

		util = (double) 100 * du->dus.io_ticks / (double) du->msec;
		if (util > 100.0)
			util = 100.0;

		fprintf(f_out, "  %s: ios=%u/%u, merge=%u/%u, ticks=%u/%u, in_queue=%u, util=%3.2f%%\n", du->name, dus->ios[0], dus->ios[1], dus->merges[0], dus->merges[1], dus->ticks[0], dus->ticks[1], dus->time_in_queue, util);
	}

	/*
	 * now free the list
	 */
	list_for_each_safe(entry, next, &disk_list) {
		list_del(entry);
		du = list_entry(entry, struct disk_util, list);
		free(du->name);
		free(du);
	}
}

static void stat_calc_dist(struct thread_stat *ts, double *io_u_dist)
{
	int i;

	/*
	 * Do depth distribution calculations
	 */
	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		io_u_dist[i] = (double) ts->io_u_map[i] / (double) ts->total_io_u;
		io_u_dist[i] *= 100.0;
	}
}

static void stat_calc_lat(struct thread_stat *ts, double *io_u_lat)
{
	int i;

	/*
	 * Do latency distribution calculations
	 */
	for (i = 0; i < FIO_IO_U_LAT_NR; i++) {
		io_u_lat[i] = (double) ts->io_u_lat[i] / (double) ts->total_io_u;
		io_u_lat[i] *= 100.0;
	}
}

static void show_ddir_status(struct group_run_stats *rs, struct thread_stat *ts,
			     int ddir)
{
	const char *ddir_str[] = { "read ", "write" };
	unsigned long min, max;
	unsigned long long bw;
	double mean, dev;
	char *io_p, *bw_p;

	if (!ts->runtime[ddir])
		return;

	bw = ts->io_bytes[ddir] / ts->runtime[ddir];
	io_p = num2str(ts->io_bytes[ddir] >> 10, 6, 1);
	bw_p = num2str(bw, 6, 1);

	fprintf(f_out, "  %s: io=%siB, bw=%siB/s, runt=%6lumsec\n", ddir_str[ddir], io_p, bw_p, ts->runtime[ddir]);

	free(io_p);
	free(bw_p);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, "    slat (msec): min=%5lu, max=%5lu, avg=%5.02f, stdev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, "    clat (msec): min=%5lu, max=%5lu, avg=%5.02f, stdev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		fprintf(f_out, "    bw (KiB/s) : min=%5lu, max=%5lu, per=%3.2f%%, avg=%5.02f, stdev=%5.02f\n", min, max, p_of_agg, mean, dev);
	}
}

static void show_thread_status(struct thread_stat *ts,
			       struct group_run_stats *rs)
{
	double usr_cpu, sys_cpu;
	unsigned long runtime;
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat[FIO_IO_U_LAT_NR];

	if (!(ts->io_bytes[0] + ts->io_bytes[1]))
		return;

	if (!ts->error)
		fprintf(f_out, "%s: (groupid=%d, jobs=%d): err=%2d: pid=%d\n", ts->name, ts->groupid, ts->members, ts->error, ts->pid);
	else
		fprintf(f_out, "%s: (groupid=%d, jobs=%d): err=%2d (%s): pid=%d\n", ts->name, ts->groupid, ts->members, ts->error, ts->verror, ts->pid);

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

	fprintf(f_out, "  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%lu\n", usr_cpu, sys_cpu, ts->ctx);

	stat_calc_dist(ts, io_u_dist);
	stat_calc_lat(ts, io_u_lat);

	fprintf(f_out, "  IO depths    : 1=%3.1f%%, 2=%3.1f%%, 4=%3.1f%%, 8=%3.1f%%, 16=%3.1f%%, 32=%3.1f%%, >=64=%3.1f%%\n", io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3], io_u_dist[4], io_u_dist[5], io_u_dist[6]);

	fprintf(f_out, "     lat (msec): 2=%3.1f%%, 4=%3.1f%%, 10=%3.1f%%, 20=%3.1f%%, 50=%3.1f%%, 100=%3.1f%%\n", io_u_lat[0], io_u_lat[1], io_u_lat[2], io_u_lat[3], io_u_lat[4], io_u_lat[5]);
	fprintf(f_out, "     lat (msec): 250=%3.1f%%, 500=%3.1f%%, 750=%3.1f%%, 1000=%3.1f%%, >=2000=%3.1f%%\n", io_u_lat[6], io_u_lat[7], io_u_lat[8], io_u_lat[9], io_u_lat[10]);

	if (ts->description)
		fprintf(f_out, "%s\n", ts->description);
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

	fprintf(f_out, ";%llu;%llu;%lu", ts->io_bytes[ddir] >> 10, bw, ts->runtime[ddir]);

	if (calc_lat(&ts->slat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, ";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		fprintf(f_out, ";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->clat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, ";%lu;%lu;%f;%f", min, max, mean, dev);
	else
		fprintf(f_out, ";%lu;%lu;%f;%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&ts->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		fprintf(f_out, ";%lu;%lu;%f%%;%f;%f", min, max, p_of_agg, mean, dev);
	} else
		fprintf(f_out, ";%lu;%lu;%f%%;%f;%f", 0UL, 0UL, 0.0, 0.0, 0.0);
}


static void show_thread_status_terse(struct thread_stat *ts,
				     struct group_run_stats *rs)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	double io_u_lat[FIO_IO_U_LAT_NR];
	double usr_cpu, sys_cpu;

	fprintf(f_out, "%s;%d;%d", ts->name, ts->groupid, ts->error);

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

	fprintf(f_out, ";%f%%;%f%%;%lu", usr_cpu, sys_cpu, ts->ctx);

	stat_calc_dist(ts, io_u_dist);
	stat_calc_lat(ts, io_u_lat);

	fprintf(f_out, ";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%", io_u_dist[0], io_u_dist[1], io_u_dist[2], io_u_dist[3], io_u_dist[4], io_u_dist[5], io_u_dist[6]);

	fprintf(f_out, ";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%\n", io_u_lat[0], io_u_lat[1], io_u_lat[2], io_u_lat[3], io_u_lat[4], io_u_lat[5]);
	fprintf(f_out, ";%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%;%3.1f%%", io_u_lat[6], io_u_lat[7], io_u_lat[8], io_u_lat[9], io_u_lat[10]);

	if (ts->description)
		fprintf(f_out, ";%s", ts->description);

	fprintf(f_out, "\n");
}

static void __sum_stat(struct io_stat *dst, struct io_stat *src, int nr)
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

static void sum_stat(struct io_stat *dst, struct io_stat *src, int nr)
{
	__sum_stat(&dst[DDIR_READ], &src[DDIR_READ], nr);
	__sum_stat(&dst[DDIR_WRITE], &src[DDIR_WRITE], nr);
}

void show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	struct thread_stat *threadstats, *ts;
	int i, j, k, nr_ts, last_ts, members;

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
		if (!td->group_reporting) {
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
		ts->clat_stat[0].min_val = -1UL;
		ts->clat_stat[1].min_val = -1UL;
		ts->slat_stat[0].min_val = -1UL;
		ts->slat_stat[1].min_val = -1UL;
		ts->bw_stat[0].min_val = -1UL;
		ts->bw_stat[1].min_val = -1UL;
	}

	j = 0;
	last_ts = -1;
	members = 0;
	for_each_td(td, i) {
		ts = &threadstats[j];

		members++;
		ts->members++;

		if (!ts->groupid) {
			/*
			 * These are per-group shared already
			 */
			ts->name = td->name;
			ts->description = td->description;
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

		sum_stat(ts->clat_stat, td->ts.clat_stat, members);
		sum_stat(ts->slat_stat, td->ts.slat_stat, members);
		sum_stat(ts->bw_stat, td->ts.bw_stat, members);

		ts->stat_io_bytes[0] += td->ts.stat_io_bytes[0];
		ts->stat_io_bytes[1] += td->ts.stat_io_bytes[1];

		ts->usr_time += td->ts.usr_time;
		ts->sys_time += td->ts.sys_time;
		ts->ctx += td->ts.ctx;

		for (k = 0; k < FIO_IO_U_MAP_NR; k++)
			ts->io_u_map[k] += td->ts.io_u_map[k];
		for (k = 0; k < FIO_IO_U_LAT_NR; k++)
			ts->io_u_lat[k] += td->ts.io_u_lat[k];

		ts->total_io_u += td->ts.total_io_u;
		ts->io_bytes[0] += td->ts.io_bytes[0];
		ts->io_bytes[1] += td->ts.io_bytes[1];

		if (ts->runtime[0] < td->ts.runtime[0])
			ts->runtime[0] = td->ts.runtime[0];
		if (ts->runtime[1] < td->ts.runtime[1])
			ts->runtime[1] = td->ts.runtime[1];

		ts->total_run_time += td->ts.total_run_time;

		if (!td->group_reporting) {
			members = 0;
			j++;
			continue;
		}
		if (last_ts == td->groupid)
			continue;

		if (last_ts != -1) {
			members = 0;
			j++;
		}

		last_ts = td->groupid;
	}

	for (i = 0; i < nr_ts; i++) {
		unsigned long long rbw, wbw;

		ts = &threadstats[i];
		rs = &runstats[ts->groupid];

		if (ts->runtime[0] < rs->min_run[0] || !rs->min_run[0])
			rs->min_run[0] = ts->runtime[0];
		if (ts->runtime[0] > rs->max_run[0])
			rs->max_run[0] = ts->runtime[0];
		if (ts->runtime[1] < rs->min_run[1] || !rs->min_run[1])
			rs->min_run[1] = ts->runtime[1];
		if (ts->runtime[1] > rs->max_run[1])
			rs->max_run[1] = ts->runtime[1];

		rbw = wbw = 0;
		if (ts->runtime[0])
			rbw = ts->io_bytes[0] / (unsigned long long) ts->runtime[0];
		if (ts->runtime[1])
			wbw = ts->io_bytes[1] / (unsigned long long) ts->runtime[1];

		if (rbw < rs->min_bw[0])
			rs->min_bw[0] = rbw;
		if (wbw < rs->min_bw[1])
			rs->min_bw[1] = wbw;
		if (rbw > rs->max_bw[0])
			rs->max_bw[0] = rbw;
		if (wbw > rs->max_bw[1])
			rs->max_bw[1] = wbw;

		rs->io_kb[0] += ts->io_bytes[0] >> 10;
		rs->io_kb[1] += ts->io_bytes[1] >> 10;
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
	is->mean += delta / (is->samples + 1.0);
	is->S += delta * (val - is->mean);

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
		     unsigned long msec)
{
	struct thread_stat *ts = &td->ts;

	add_stat_sample(&ts->clat_stat[ddir], msec);

	if (ts->clat_log)
		add_log_sample(td, ts->clat_log, msec, ddir);
}

void add_slat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long msec)
{
	struct thread_stat *ts = &td->ts;

	add_stat_sample(&ts->slat_stat[ddir], msec);

	if (ts->slat_log)
		add_log_sample(td, ts->slat_log, msec, ddir);
}

void add_bw_sample(struct thread_data *td, enum fio_ddir ddir,
		   struct timeval *t)
{
	struct thread_stat *ts = &td->ts;
	unsigned long spent = mtime_since(&ts->stat_sample_time[ddir], t);
	unsigned long rate;

	if (spent < td->bw_avg_time)
		return;

	rate = (td->this_io_bytes[ddir] - ts->stat_io_bytes[ddir]) / spent;
	add_stat_sample(&ts->bw_stat[ddir], rate);

	if (ts->bw_log)
		add_log_sample(td, ts->bw_log, rate, ddir);

	fio_gettime(&ts->stat_sample_time[ddir], NULL);
	ts->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
}
