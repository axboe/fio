#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <libgen.h>
#include <math.h>
#include <assert.h>

#include "fio.h"
#include "smalloc.h"
#include "diskutil.h"
#include "helper_thread.h"

static int last_majdev, last_mindev;
static struct disk_util *last_du;

static struct fio_mutex *disk_util_mutex;

static struct disk_util *__init_per_file_disk_util(struct thread_data *td,
		int majdev, int mindev, char *path);

static void disk_util_free(struct disk_util *du)
{
	if (du == last_du)
		last_du = NULL;

	while (!flist_empty(&du->slaves)) {
		struct disk_util *slave;

		slave = flist_first_entry(&du->slaves, struct disk_util, slavelist);
		flist_del(&slave->slavelist);
		slave->users--;
	}

	fio_mutex_remove(du->lock);
	free(du->sysfs_root);
	sfree(du);
}

static int get_io_ticks(struct disk_util *du, struct disk_util_stat *dus)
{
	unsigned in_flight;
	unsigned long long sectors[2];
	char line[256];
	FILE *f;
	char *p;
	int ret;

	dprint(FD_DISKUTIL, "open stat file: %s\n", du->path);

	f = fopen(du->path, "r");
	if (!f)
		return 1;

	p = fgets(line, sizeof(line), f);
	if (!p) {
		fclose(f);
		return 1;
	}

	dprint(FD_DISKUTIL, "%s: %s", du->path, p);

	ret = sscanf(p, "%llu %llu %llu %llu %llu %llu %llu %llu %u %llu %llu\n",
				(unsigned long long *) &dus->s.ios[0],
				(unsigned long long *) &dus->s.merges[0],
				&sectors[0],
				(unsigned long long *) &dus->s.ticks[0],
				(unsigned long long *) &dus->s.ios[1],
				(unsigned long long *) &dus->s.merges[1],
				&sectors[1],
				(unsigned long long *) &dus->s.ticks[1],
				&in_flight,
				(unsigned long long *) &dus->s.io_ticks,
				(unsigned long long *) &dus->s.time_in_queue);
	fclose(f);
	dprint(FD_DISKUTIL, "%s: stat read ok? %d\n", du->path, ret == 1);
	dus->s.sectors[0] = sectors[0];
	dus->s.sectors[1] = sectors[1];
	return ret != 11;
}

static void update_io_tick_disk(struct disk_util *du)
{
	struct disk_util_stat __dus, *dus, *ldus;
	struct timeval t;

	if (!du->users)
		return;
	if (get_io_ticks(du, &__dus))
		return;

	dus = &du->dus;
	ldus = &du->last_dus;

	dus->s.sectors[0] += (__dus.s.sectors[0] - ldus->s.sectors[0]);
	dus->s.sectors[1] += (__dus.s.sectors[1] - ldus->s.sectors[1]);
	dus->s.ios[0] += (__dus.s.ios[0] - ldus->s.ios[0]);
	dus->s.ios[1] += (__dus.s.ios[1] - ldus->s.ios[1]);
	dus->s.merges[0] += (__dus.s.merges[0] - ldus->s.merges[0]);
	dus->s.merges[1] += (__dus.s.merges[1] - ldus->s.merges[1]);
	dus->s.ticks[0] += (__dus.s.ticks[0] - ldus->s.ticks[0]);
	dus->s.ticks[1] += (__dus.s.ticks[1] - ldus->s.ticks[1]);
	dus->s.io_ticks += (__dus.s.io_ticks - ldus->s.io_ticks);
	dus->s.time_in_queue += (__dus.s.time_in_queue - ldus->s.time_in_queue);

	fio_gettime(&t, NULL);
	dus->s.msec += mtime_since(&du->time, &t);
	memcpy(&du->time, &t, sizeof(t));
	memcpy(&ldus->s, &__dus.s, sizeof(__dus.s));
}

int update_io_ticks(void)
{
	struct flist_head *entry;
	struct disk_util *du;
	int ret = 0;

	dprint(FD_DISKUTIL, "update io ticks\n");

	fio_mutex_down(disk_util_mutex);

	if (!helper_should_exit()) {
		flist_for_each(entry, &disk_list) {
			du = flist_entry(entry, struct disk_util, list);
			update_io_tick_disk(du);
		}
	} else
		ret = 1;

	fio_mutex_up(disk_util_mutex);
	return ret;
}

static struct disk_util *disk_util_exists(int major, int minor)
{
	struct flist_head *entry;
	struct disk_util *du;

	fio_mutex_down(disk_util_mutex);

	flist_for_each(entry, &disk_list) {
		du = flist_entry(entry, struct disk_util, list);

		if (major == du->major && minor == du->minor) {
			fio_mutex_up(disk_util_mutex);
			return du;
		}
	}

	fio_mutex_up(disk_util_mutex);
	return NULL;
}

static int get_device_numbers(char *file_name, int *maj, int *min)
{
	struct stat st;
	int majdev, mindev;
	char tempname[PATH_MAX], *p;

	if (!lstat(file_name, &st)) {
		if (S_ISBLK(st.st_mode)) {
			majdev = major(st.st_rdev);
			mindev = minor(st.st_rdev);
		} else if (S_ISCHR(st.st_mode)) {
			majdev = major(st.st_rdev);
			mindev = minor(st.st_rdev);
			if (fio_lookup_raw(st.st_rdev, &majdev, &mindev))
				return -1;
		} else if (S_ISFIFO(st.st_mode))
			return -1;
		else {
			majdev = major(st.st_dev);
			mindev = minor(st.st_dev);
		}
	} else {
		/*
		 * must be a file, open "." in that path
		 */
		tempname[PATH_MAX - 1] = '\0';
		strncpy(tempname, file_name, PATH_MAX - 1);
		p = dirname(tempname);
		if (stat(p, &st)) {
			perror("disk util stat");
			return -1;
		}

		majdev = major(st.st_dev);
		mindev = minor(st.st_dev);
	}

	*min = mindev;
	*maj = majdev;

	return 0;
}

static int read_block_dev_entry(char *path, int *maj, int *min)
{
	char line[256], *p;
	FILE *f;

	f = fopen(path, "r");
	if (!f) {
		perror("open path");
		return 1;
	}

	p = fgets(line, sizeof(line), f);
	fclose(f);

	if (!p)
		return 1;

	if (sscanf(p, "%u:%u", maj, min) != 2)
		return 1;

	return 0;
}

static void find_add_disk_slaves(struct thread_data *td, char *path,
				 struct disk_util *masterdu)
{
	DIR *dirhandle = NULL;
	struct dirent *dirent = NULL;
	char slavesdir[PATH_MAX], temppath[PATH_MAX], slavepath[PATH_MAX];
	struct disk_util *slavedu = NULL;
	int majdev, mindev;
	ssize_t linklen;

	sprintf(slavesdir, "%s/%s", path, "slaves");
	dirhandle = opendir(slavesdir);
	if (!dirhandle)
		return;

	while ((dirent = readdir(dirhandle)) != NULL) {
		if (!strcmp(dirent->d_name, ".") ||
		    !strcmp(dirent->d_name, ".."))
			continue;

		sprintf(temppath, "%s/%s", slavesdir, dirent->d_name);
		/* Can we always assume that the slaves device entries
		 * are links to the real directories for the slave
		 * devices?
		 */
		linklen = readlink(temppath, slavepath, PATH_MAX - 1);
		if (linklen  < 0) {
			perror("readlink() for slave device.");
			closedir(dirhandle);
			return;
		}
		slavepath[linklen] = '\0';

		sprintf(temppath, "%s/%s/dev", slavesdir, slavepath);
		if (read_block_dev_entry(temppath, &majdev, &mindev)) {
			perror("Error getting slave device numbers.");
			closedir(dirhandle);
			return;
		}

		/*
		 * See if this maj,min already exists
		 */
		slavedu = disk_util_exists(majdev, mindev);
		if (slavedu)
			continue;

		sprintf(temppath, "%s/%s", slavesdir, slavepath);
		__init_per_file_disk_util(td, majdev, mindev, temppath);
		slavedu = disk_util_exists(majdev, mindev);

		/* Should probably use an assert here. slavedu should
		 * always be present at this point. */
		if (slavedu) {
			slavedu->users++;
			flist_add_tail(&slavedu->slavelist, &masterdu->slaves);
		}
	}

	closedir(dirhandle);
}

static struct disk_util *disk_util_add(struct thread_data *td, int majdev,
				       int mindev, char *path)
{
	struct disk_util *du, *__du;
	struct flist_head *entry;
	int l;

	dprint(FD_DISKUTIL, "add maj/min %d/%d: %s\n", majdev, mindev, path);

	du = smalloc(sizeof(*du));
	if (!du)
		return NULL;

	memset(du, 0, sizeof(*du));
	INIT_FLIST_HEAD(&du->list);
	l = snprintf(du->path, sizeof(du->path), "%s/stat", path);
	if (l < 0 || l >= sizeof(du->path)) {
		log_err("constructed path \"%.100s[...]/stat\" larger than buffer (%zu bytes)\n",
			path, sizeof(du->path) - 1);
		sfree(du);
		return NULL;
	}
	strncpy((char *) du->dus.name, basename(path), FIO_DU_NAME_SZ - 1);
	du->sysfs_root = strdup(path);
	du->major = majdev;
	du->minor = mindev;
	INIT_FLIST_HEAD(&du->slavelist);
	INIT_FLIST_HEAD(&du->slaves);
	du->lock = fio_mutex_init(FIO_MUTEX_UNLOCKED);
	du->users = 0;

	fio_mutex_down(disk_util_mutex);

	flist_for_each(entry, &disk_list) {
		__du = flist_entry(entry, struct disk_util, list);

		dprint(FD_DISKUTIL, "found %s in list\n", __du->dus.name);

		if (!strcmp((char *) du->dus.name, (char *) __du->dus.name)) {
			disk_util_free(du);
			fio_mutex_up(disk_util_mutex);
			return __du;
		}
	}

	dprint(FD_DISKUTIL, "add %s to list\n", du->dus.name);

	fio_gettime(&du->time, NULL);
	get_io_ticks(du, &du->last_dus);

	flist_add_tail(&du->list, &disk_list);
	fio_mutex_up(disk_util_mutex);

	find_add_disk_slaves(td, path, du);
	return du;
}

static int check_dev_match(int majdev, int mindev, char *path)
{
	int major, minor;

	if (read_block_dev_entry(path, &major, &minor))
		return 1;

	if (majdev == major && mindev == minor)
		return 0;

	return 1;
}

static int find_block_dir(int majdev, int mindev, char *path, int link_ok)
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
			if (!check_dev_match(majdev, mindev, full_path)) {
				found = 1;
				break;
			}
		}

		if (link_ok) {
			if (stat(full_path, &st) == -1) {
				perror("stat");
				break;
			}
		} else {
			if (lstat(full_path, &st) == -1) {
				perror("stat");
				break;
			}
		}

		if (!S_ISDIR(st.st_mode) || S_ISLNK(st.st_mode))
			continue;

		found = find_block_dir(majdev, mindev, full_path, 0);
		if (found) {
			strcpy(path, full_path);
			break;
		}
	}

	closedir(D);
	return found;
}

static struct disk_util *__init_per_file_disk_util(struct thread_data *td,
						   int majdev, int mindev,
						   char *path)
{
	struct stat st;
	char tmp[PATH_MAX];
	char *p;

	/*
	 * If there's a ../queue/ directory there, we are inside a partition.
	 * Check if that is the case and jump back. For loop/md/dm etc we
	 * are already in the right spot.
	 */
	sprintf(tmp, "%s/../queue", path);
	if (!stat(tmp, &st)) {
		p = dirname(path);
		sprintf(tmp, "%s/queue", p);
		if (stat(tmp, &st)) {
			log_err("unknown sysfs layout\n");
			return NULL;
		}
		tmp[PATH_MAX - 1] = '\0';
		strncpy(tmp, p, PATH_MAX - 1);
		sprintf(path, "%s", tmp);
	}

	return disk_util_add(td, majdev, mindev, path);
}

static struct disk_util *init_per_file_disk_util(struct thread_data *td,
						 char *filename)
{

	char foo[PATH_MAX];
	struct disk_util *du;
	int mindev, majdev;

	if (get_device_numbers(filename, &majdev, &mindev))
		return NULL;

	dprint(FD_DISKUTIL, "%s belongs to maj/min %d/%d\n", filename, majdev,
			mindev);

	du = disk_util_exists(majdev, mindev);
	if (du)
		return du;

	/*
	 * for an fs without a device, we will repeatedly stat through
	 * sysfs which can take oodles of time for thousands of files. so
	 * cache the last lookup and compare with that before going through
	 * everything again.
	 */
	if (mindev == last_mindev && majdev == last_majdev)
		return last_du;

	last_mindev = mindev;
	last_majdev = majdev;

	sprintf(foo, "/sys/block");
	if (!find_block_dir(majdev, mindev, foo, 1))
		return NULL;

	return __init_per_file_disk_util(td, majdev, mindev, foo);
}

static struct disk_util *__init_disk_util(struct thread_data *td,
					  struct fio_file *f)
{
	return init_per_file_disk_util(td, f->file_name);
}

void init_disk_util(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	if (!td->o.do_disk_util ||
	    td_ioengine_flagged(td, FIO_DISKLESSIO | FIO_NODISKUTIL))
		return;

	for_each_file(td, f, i)
		f->du = __init_disk_util(td, f);
}

static void show_agg_stats(struct disk_util_agg *agg, int terse,
			   struct buf_output *out)
{
	if (!agg->slavecount)
		return;

	if (!terse) {
		log_buf(out, ", aggrios=%llu/%llu, aggrmerge=%llu/%llu, "
			 "aggrticks=%llu/%llu, aggrin_queue=%llu, "
			 "aggrutil=%3.2f%%",
			(unsigned long long) agg->ios[0] / agg->slavecount,
			(unsigned long long) agg->ios[1] / agg->slavecount,
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

void disk_util_prune_entries(void)
{
	fio_mutex_down(disk_util_mutex);

	while (!flist_empty(&disk_list)) {
		struct disk_util *du;

		du = flist_first_entry(&disk_list, struct disk_util, list);
		flist_del(&du->list);
		disk_util_free(du);
	}

	last_majdev = last_mindev = -1;
	fio_mutex_up(disk_util_mutex);
	fio_mutex_remove(disk_util_mutex);
}

void print_disk_util(struct disk_util_stat *dus, struct disk_util_agg *agg,
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

		log_buf(out, "  %s: ios=%llu/%llu, merge=%llu/%llu, "
			 "ticks=%llu/%llu, in_queue=%llu, util=%3.2f%%",
				dus->name,
				(unsigned long long) dus->s.ios[0],
				(unsigned long long) dus->s.ios[1],
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

void json_array_add_disk_util(struct disk_util_stat *dus,
		struct disk_util_agg *agg, struct json_array *array)
{
	struct json_object *obj;
	double util = 0;

	if (dus->s.msec)
		util = (double) 100 * dus->s.io_ticks / (double) dus->s.msec;
	if (util > 100.0)
		util = 100.0;

	obj = json_create_object();
	json_array_add_value_object(array, obj);

	json_object_add_value_string(obj, "name", dus->name);
	json_object_add_value_int(obj, "read_ios", dus->s.ios[0]);
	json_object_add_value_int(obj, "write_ios", dus->s.ios[1]);
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

void show_disk_util(int terse, struct json_object *parent,
		    struct buf_output *out)
{
	struct flist_head *entry;
	struct disk_util *du;
	bool do_json;

	if (!disk_util_mutex)
		return;

	fio_mutex_down(disk_util_mutex);

	if (flist_empty(&disk_list)) {
		fio_mutex_up(disk_util_mutex);
		return;
	}

	if ((output_format & FIO_OUTPUT_JSON) && parent)
		do_json = true;
	else
		do_json = false;

	if (!terse && !do_json)
		log_buf(out, "\nDisk stats (read/write):\n");

	if (do_json)
		json_object_add_disk_utils(parent, &disk_list);
	else if (output_format & ~(FIO_OUTPUT_JSON | FIO_OUTPUT_JSON_PLUS)) {
		flist_for_each(entry, &disk_list) {
			du = flist_entry(entry, struct disk_util, list);

			aggregate_slaves_stats(du);
			print_disk_util(&du->dus, &du->agg, terse, out);
		}
	}

	fio_mutex_up(disk_util_mutex);
}

void setup_disk_util(void)
{
	disk_util_mutex = fio_mutex_init(FIO_MUTEX_UNLOCKED);
}
