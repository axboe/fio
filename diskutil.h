#ifndef FIO_DISKUTIL_H
#define FIO_DISKUTIL_H

/*
 * Disk utils as read in /sys/block/<dev>/stat
 */
struct disk_util_stat {
	unsigned ios[2];
	unsigned merges[2];
	unsigned long long sectors[2];
	unsigned ticks[2];
	unsigned io_ticks;
	unsigned time_in_queue;
};

/*
 * Per-device disk util management
 */
struct disk_util {
	struct flist_head list;
	/* If this disk is a slave, hook it into the master's
	 * list using this head.
	 */
	struct flist_head slavelist;

	char *name;
	char *sysfs_root;
	char path[256];
	int major, minor;

	struct disk_util_stat dus;
	struct disk_util_stat last_dus;

	/* For software raids, this entry maintains pointers to the
	 * entries for the slave devices. The disk_util entries for
	 * the slaves devices should primarily be maintained through
	 * the disk_list list, i.e. for memory allocation and
	 * de-allocation, etc. Whereas this list should be used only
	 * for aggregating a software RAID's disk util figures.
	 */
	struct flist_head slaves;

	unsigned long msec;
	struct timeval time;

	struct fio_mutex *lock;
	unsigned long users;
};

static inline void disk_util_inc(struct disk_util *du)
{
	if (du) {
		fio_mutex_down(du->lock);
		du->users++;
		fio_mutex_up(du->lock);
	}
}

static inline void disk_util_dec(struct disk_util *du)
{
	if (du) {
		fio_mutex_down(du->lock);
		du->users--;
		fio_mutex_up(du->lock);
	}
}

#define DISK_UTIL_MSEC	(250)

/*
 * disk util stuff
 */
#ifdef FIO_HAVE_DISK_UTIL
extern void show_disk_util(void);
extern void init_disk_util(struct thread_data *);
extern void update_io_ticks(void);
#else
#define show_disk_util()
#define init_disk_util(td)
#define update_io_ticks()
#endif

#endif
