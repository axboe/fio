#ifndef FIO_DISKUTIL_H
#define FIO_DISKUTIL_H
#define FIO_DU_NAME_SZ		64

#include <stdint.h>
#include <limits.h>

#include "helper_thread.h"
#include "fio_sem.h"
#include "flist.h"
#include "lib/ieee754.h"

/**
 * @ios: Number of I/O operations that have been completed successfully.
 * @merges: Number of I/O operations that have been merged.
 * @sectors: I/O size in 512-byte units.
 * @ticks: Time spent on I/O in milliseconds.
 * @io_ticks: CPU time spent on I/O in milliseconds.
 * @time_in_queue: Weighted time spent doing I/O in milliseconds.
 *
 * For the array members, index 0 refers to reads and index 1 refers to writes.
 */
struct disk_util_stats {
	uint64_t ios[2];
	uint64_t merges[2];
	uint64_t sectors[2];
	uint64_t ticks[2];
	uint64_t io_ticks;
	uint64_t time_in_queue;
	uint64_t msec;
};

/*
 * Disk utilization as read from /sys/block/<dev>/stat
 */
struct disk_util_stat {
	uint8_t name[FIO_DU_NAME_SZ];
	struct disk_util_stats s;
};

struct disk_util_agg {
	uint64_t ios[2];
	uint64_t merges[2];
	uint64_t sectors[2];
	uint64_t ticks[2];
	uint64_t io_ticks;
	uint64_t time_in_queue;
	uint32_t slavecount;
	uint32_t pad;
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

	char *sysfs_root;
	char path[PATH_MAX];
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

	struct timespec time;

	struct fio_sem *lock;
	unsigned long users;
};

static inline void disk_util_mod(struct disk_util *du, int val)
{
	if (du) {
		struct flist_head *n;

		fio_sem_down(du->lock);
		du->users += val;

		flist_for_each(n, &du->slavelist) {
			struct disk_util *slave;

			slave = flist_entry(n, struct disk_util, slavelist);
			slave->users += val;
		}
		fio_sem_up(du->lock);
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
extern void init_disk_util(struct thread_data *);
extern int update_io_ticks(void);
extern void setup_disk_util(void);
extern void disk_util_prune_entries(void);
#else
/* keep this as a function to avoid a warning in handle_du() */
#define disk_util_prune_entries()
#define init_disk_util(td)
#define setup_disk_util()

static inline int update_io_ticks(void)
{
	return helper_should_exit();
}
#endif

#endif
