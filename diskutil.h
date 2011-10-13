#ifndef FIO_DISKUTIL_H
#define FIO_DISKUTIL_H

#define FIO_DU_NAME_SZ		64

/*
 * Disk utils as read in /sys/block/<dev>/stat
 */
struct disk_util_stat {
	uint8_t name[FIO_DU_NAME_SZ];
	uint32_t ios[2];
	uint32_t merges[2];
	uint64_t sectors[2];
	uint32_t ticks[2];
	uint32_t io_ticks;
	uint32_t time_in_queue;
	uint64_t msec;
};

struct disk_util_agg {
	uint32_t ios[2];
	uint32_t merges[2];
	uint64_t sectors[2];
	uint32_t ticks[2];
	uint32_t io_ticks;
	uint32_t time_in_queue;
	uint32_t slavecount;
	fio_fp64_t max_util;
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

	struct disk_util_agg agg;

	/* For software raids, this entry maintains pointers to the
	 * entries for the slave devices. The disk_util entries for
	 * the slaves devices should primarily be maintained through
	 * the disk_list list, i.e. for memory allocation and
	 * de-allocation, etc. Whereas this list should be used only
	 * for aggregating a software RAID's disk util figures.
	 */
	struct flist_head slaves;

	struct timeval time;

	struct fio_mutex *lock;
	unsigned long users;
};

static inline void disk_util_mod(struct disk_util *du, int val)
{
	if (du) {
		struct flist_head *n;

		fio_mutex_down(du->lock);
		du->users += val;

		flist_for_each(n, &du->slavelist) {
			struct disk_util *slave;

			slave = flist_entry(n, struct disk_util, slavelist);
			slave->users += val;
		}
		fio_mutex_up(du->lock);
	}
}
static inline void disk_util_inc(struct disk_util *du)
{
	disk_util_mod(du, 1);
}

static inline void disk_util_dec(struct disk_util *du)
{
	disk_util_mod(du, -1);
}

#define DISK_UTIL_MSEC	(250)

extern struct flist_head disk_list;

/*
 * disk util stuff
 */
#ifdef FIO_HAVE_DISK_UTIL
extern void print_disk_util(struct disk_util_stat *, struct disk_util_agg *);
extern void show_disk_util(void);
extern void free_disk_util(void);
extern void init_disk_util(struct thread_data *);
extern void update_io_ticks(void);
#else
#define print_disk_util(dus, agg)
#define show_disk_util()
#define free_disk_util()
#define init_disk_util(td)
#define update_io_ticks()
#endif

#endif
