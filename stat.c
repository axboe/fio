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
	struct disk_util *du = malloc(sizeof(*du));

	memset(du, 0, sizeof(*du));
	INIT_LIST_HEAD(&du->list);
	sprintf(du->path, "%s/stat", path);
	du->name = strdup(basename(path));
	du->dev = dev;

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

	if (!td->do_disk_util)
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
	getrusage(RUSAGE_SELF, &td->ru_end);

	td->usr_time += mtime_since(&td->ru_start.ru_utime, &td->ru_end.ru_utime);
	td->sys_time += mtime_since(&td->ru_start.ru_stime, &td->ru_end.ru_stime);
	td->ctx += td->ru_end.ru_nvcsw + td->ru_end.ru_nivcsw - (td->ru_start.ru_nvcsw + td->ru_start.ru_nivcsw);

	
	memcpy(&td->ru_start, &td->ru_end, sizeof(td->ru_end));
}

static int calc_lat(struct io_stat *is, unsigned long *min, unsigned long *max,
		    double *mean, double *dev)
{
	double n;

	if (is->samples == 0)
		return 0;

	*min = is->min_val;
	*max = is->max_val;

	n = (double) is->samples;
	*mean = (double) is->val / n;
	*dev = sqrt(((double) is->val_sq - (*mean * *mean) / n) / (n - 1));

	return 1;
}

static void show_group_stats(struct group_run_stats *rs, int id)
{
	fprintf(f_out, "\nRun status group %d (all jobs):\n", id);

	if (rs->max_run[DDIR_READ])
		fprintf(f_out, "   READ: io=%lluMiB, aggrb=%llu, minb=%llu, maxb=%llu, mint=%llumsec, maxt=%llumsec\n", rs->io_kb[0] >> 10, rs->agg[0], rs->min_bw[0], rs->max_bw[0], rs->min_run[0], rs->max_run[0]);
	if (rs->max_run[DDIR_WRITE])
		fprintf(f_out, "  WRITE: io=%lluMiB, aggrb=%llu, minb=%llu, maxb=%llu, mint=%llumsec, maxt=%llumsec\n", rs->io_kb[1] >> 10, rs->agg[1], rs->min_bw[1], rs->max_bw[1], rs->min_run[1], rs->max_run[1]);
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

static void show_ddir_status(struct thread_data *td, struct group_run_stats *rs,
			     int ddir)
{
	const char *ddir_str[] = { "read ", "write" };
	unsigned long min, max;
	unsigned long long bw;
	double mean, dev;

	if (!td->runtime[ddir])
		return;

	bw = td->io_bytes[ddir] / td->runtime[ddir];
	fprintf(f_out, "  %s: io=%6lluMiB, bw=%6lluKiB/s, runt=%6lumsec\n", ddir_str[ddir], td->io_bytes[ddir] >> 20, bw, td->runtime[ddir]);

	if (calc_lat(&td->slat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, "    slat (msec): min=%5lu, max=%5lu, avg=%5.02f, dev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&td->clat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, "    clat (msec): min=%5lu, max=%5lu, avg=%5.02f, dev=%5.02f\n", min, max, mean, dev);

	if (calc_lat(&td->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		fprintf(f_out, "    bw (KiB/s) : min=%5lu, max=%5lu, per=%3.2f%%, avg=%5.02f, dev=%5.02f\n", min, max, p_of_agg, mean, dev);
	}
}

static void show_thread_status(struct thread_data *td,
			       struct group_run_stats *rs)
{
	double usr_cpu, sys_cpu;
	unsigned long runtime;

	if (!(td->io_bytes[0] + td->io_bytes[1]) && !td->error)
		return;

	fprintf(f_out, "%s: (groupid=%d): err=%2d:\n",td->name, td->groupid, td->error);

	show_ddir_status(td, rs, td->ddir);
	if (td->io_bytes[td->ddir ^ 1])
		show_ddir_status(td, rs, td->ddir ^ 1);

	runtime = mtime_since(&td->epoch, &td->end_time);
	if (runtime) {
		double runt = (double) runtime;

		usr_cpu = (double) td->usr_time * 100 / runt;
		sys_cpu = (double) td->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	fprintf(f_out, "  cpu          : usr=%3.2f%%, sys=%3.2f%%, ctx=%lu\n", usr_cpu, sys_cpu, td->ctx);
}

static void show_ddir_status_terse(struct thread_data *td,
				   struct group_run_stats *rs, int ddir)
{
	unsigned long min, max;
	unsigned long long bw;
	double mean, dev;

	bw = 0;
	if (td->runtime[ddir])
		bw = td->io_bytes[ddir] / td->runtime[ddir];

	fprintf(f_out, ",%llu,%llu,%lu", td->io_bytes[ddir] >> 10, bw, td->runtime[ddir]);

	if (calc_lat(&td->slat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, ",%lu,%lu,%f,%f", min, max, mean, dev);
	else
		fprintf(f_out, ",%lu,%lu,%f,%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&td->clat_stat[ddir], &min, &max, &mean, &dev))
		fprintf(f_out, ",%lu,%lu,%f,%f", min, max, mean, dev);
	else
		fprintf(f_out, ",%lu,%lu,%f,%f", 0UL, 0UL, 0.0, 0.0);

	if (calc_lat(&td->bw_stat[ddir], &min, &max, &mean, &dev)) {
		double p_of_agg;

		p_of_agg = mean * 100 / (double) rs->agg[ddir];
		fprintf(f_out, ",%lu,%lu,%f%%,%f,%f", min, max, p_of_agg, mean, dev);
	} else
		fprintf(f_out, ",%lu,%lu,%f%%,%f,%f", 0UL, 0UL, 0.0, 0.0, 0.0);
		
}


static void show_thread_status_terse(struct thread_data *td,
				     struct group_run_stats *rs)
{
	double usr_cpu, sys_cpu;

	fprintf(f_out, "%s,%d,%d",td->name, td->groupid, td->error);

	show_ddir_status_terse(td, rs, 0);
	show_ddir_status_terse(td, rs, 1);

	if (td->runtime[0] + td->runtime[1]) {
		double runt = (double) (td->runtime[0] + td->runtime[1]);

		usr_cpu = (double) td->usr_time * 100 / runt;
		sys_cpu = (double) td->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	fprintf(f_out, ",%f%%,%f%%,%lu\n", usr_cpu, sys_cpu, td->ctx);
}

void show_run_stats(void)
{
	struct group_run_stats *runstats, *rs;
	struct thread_data *td;
	int i;

	runstats = malloc(sizeof(struct group_run_stats) * (groupid + 1));

	for (i = 0; i < groupid + 1; i++) {
		rs = &runstats[i];

		memset(rs, 0, sizeof(*rs));
		rs->min_bw[0] = rs->min_run[0] = ~0UL;
		rs->min_bw[1] = rs->min_run[1] = ~0UL;
	}

	for_each_td(td, i) {
		unsigned long long rbw, wbw;

		if (td->error) {
			fprintf(f_out, "%s: %s\n", td->name, td->verror);
			continue;
		}

		rs = &runstats[td->groupid];

		if (td->runtime[0] < rs->min_run[0] || !rs->min_run[0])
			rs->min_run[0] = td->runtime[0];
		if (td->runtime[0] > rs->max_run[0])
			rs->max_run[0] = td->runtime[0];
		if (td->runtime[1] < rs->min_run[1] || !rs->min_run[1])
			rs->min_run[1] = td->runtime[1];
		if (td->runtime[1] > rs->max_run[1])
			rs->max_run[1] = td->runtime[1];

		rbw = wbw = 0;
		if (td->runtime[0])
			rbw = td->io_bytes[0] / (unsigned long long) td->runtime[0];
		if (td->runtime[1])
			wbw = td->io_bytes[1] / (unsigned long long) td->runtime[1];

		if (rbw < rs->min_bw[0])
			rs->min_bw[0] = rbw;
		if (wbw < rs->min_bw[1])
			rs->min_bw[1] = wbw;
		if (rbw > rs->max_bw[0])
			rs->max_bw[0] = rbw;
		if (wbw > rs->max_bw[1])
			rs->max_bw[1] = wbw;

		rs->io_kb[0] += td->io_bytes[0] >> 10;
		rs->io_kb[1] += td->io_bytes[1] >> 10;
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

	for_each_td(td, i) {
		rs = &runstats[td->groupid];

		if (terse_output)
			show_thread_status_terse(td, rs);
		else
			show_thread_status(td, rs);
	}

	if (!terse_output) {
		for (i = 0; i < groupid + 1; i++)
			show_group_stats(&runstats[i], i);

		show_disk_util();
	}

	free(runstats);
}

static inline void add_stat_sample(struct io_stat *is, unsigned long val)
{
	if (val > is->max_val)
		is->max_val = val;
	if (val < is->min_val)
		is->min_val = val;

	is->val += val;
	is->val_sq += val * val;
	is->samples++;
}

static void add_log_sample(struct thread_data *td, struct io_log *iolog,
			   unsigned long val, enum fio_ddir ddir)
{
	if (iolog->nr_samples == iolog->max_samples) {
		int new_size = sizeof(struct io_sample) * iolog->max_samples*2;

		iolog->log = realloc(iolog->log, new_size);
		iolog->max_samples <<= 1;
	}

	iolog->log[iolog->nr_samples].val = val;
	iolog->log[iolog->nr_samples].time = mtime_since_now(&td->epoch);
	iolog->log[iolog->nr_samples].ddir = ddir;
	iolog->nr_samples++;
}

void add_clat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long msec)
{
	add_stat_sample(&td->clat_stat[ddir], msec);

	if (td->clat_log)
		add_log_sample(td, td->clat_log, msec, ddir);
}

void add_slat_sample(struct thread_data *td, enum fio_ddir ddir,
		     unsigned long msec)
{
	add_stat_sample(&td->slat_stat[ddir], msec);

	if (td->slat_log)
		add_log_sample(td, td->slat_log, msec, ddir);
}

void add_bw_sample(struct thread_data *td, enum fio_ddir ddir,
		   struct timeval *t)
{
	unsigned long spent = mtime_since(&td->stat_sample_time[ddir], t);
	unsigned long rate;

	if (spent < td->bw_avg_time)
		return;

	rate = (td->this_io_bytes[ddir] - td->stat_io_bytes[ddir]) / spent;
	add_stat_sample(&td->bw_stat[ddir], rate);

	if (td->bw_log)
		add_log_sample(td, td->bw_log, rate, ddir);

	fio_gettime(&td->stat_sample_time[ddir], NULL);
	td->stat_io_bytes[ddir] = td->this_io_bytes[ddir];
}


