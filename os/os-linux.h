#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#define	FIO_OS	os_linux

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <linux/unistd.h>
#include <linux/raw.h>
#include <linux/major.h>

#include "binject.h"
#include "../file.h"

#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_SGIO
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_IOSCHED_SWITCH
#define FIO_HAVE_ODIRECT
#define FIO_HAVE_HUGETLB
#define FIO_HAVE_RAWBIND
#define FIO_HAVE_BLKTRACE
#define FIO_HAVE_PSHARED_MUTEX
#define FIO_HAVE_CL_SIZE
#define FIO_HAVE_CGROUPS
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_BINJECT
#define FIO_HAVE_GETTID
#define FIO_USE_GENERIC_INIT_RANDOM_STATE

#ifdef MAP_HUGETLB
#define FIO_HAVE_MMAP_HUGE
#endif

#define OS_MAP_ANON		MAP_ANONYMOUS

typedef cpu_set_t os_cpu_mask_t;

typedef struct drand48_data os_random_state_t;

#ifdef CONFIG_3ARG_AFFINITY
#define fio_setaffinity(pid, cpumask)		\
	sched_setaffinity((pid), sizeof(cpumask), &(cpumask))
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), sizeof(cpu_set_t), (ptr))
#elif defined(CONFIG_2ARG_AFFINITY)
#define fio_setaffinity(pid, cpumask)	\
	sched_setaffinity((pid), &(cpumask))
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), (ptr))
#endif

#define fio_cpu_clear(mask, cpu)	(void) CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)		(void) CPU_SET((cpu), (mask))
#define fio_cpu_isset(mask, cpu)	CPU_ISSET((cpu), (mask))
#define fio_cpu_count(mask)		CPU_COUNT((mask))

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
	CPU_ZERO(mask);
	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return 0;
}

#define FIO_MAX_CPUS			CPU_SETSIZE

enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_BITS		16
#define IOPRIO_CLASS_SHIFT	13

static inline int ioprio_set(int which, int who, int ioprio_class, int ioprio)
{
	/*
	 * If no class is set, assume BE
	 */
	if (!ioprio_class)
		ioprio_class = IOPRIO_CLASS_BE;

	ioprio |= ioprio_class << IOPRIO_CLASS_SHIFT;
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

static inline int gettid(void)
{
	return syscall(__NR_gettid);
}

#define SPLICE_DEF_SIZE	(64*1024)

#ifndef BLKGETSIZE64
#define BLKGETSIZE64	_IOR(0x12,114,size_t)
#endif

#ifndef BLKFLSBUF
#define BLKFLSBUF	_IO(0x12,97)
#endif

#ifndef BLKDISCARD
#define BLKDISCARD	_IO(0x12,119)
#endif

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ioctl(f->fd, BLKFLSBUF);
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	if (!ioctl(f->fd, BLKGETSIZE64, bytes))
		return 0;

	return errno;
}

static inline unsigned long long os_phys_mem(void)
{
	long pagesize, pages;

	pagesize = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (pages == -1 || pagesize == -1)
		return 0;

	return (unsigned long long) pages * (unsigned long long) pagesize;
}

static inline void os_random_seed(unsigned long seed, os_random_state_t *rs)
{
	srand48_r(seed, rs);
}

static inline long os_random_long(os_random_state_t *rs)
{
	long val;

	lrand48_r(rs, &val);
	return val;
}

static inline int fio_lookup_raw(dev_t dev, int *majdev, int *mindev)
{
	struct raw_config_request rq;
	int fd;

	if (major(dev) != RAW_MAJOR)
		return 1;

	/*
	 * we should be able to find /dev/rawctl or /dev/raw/rawctl
	 */
	fd = open("/dev/rawctl", O_RDONLY);
	if (fd < 0) {
		fd = open("/dev/raw/rawctl", O_RDONLY);
		if (fd < 0)
			return 1;
	}

	rq.raw_minor = minor(dev);
	if (ioctl(fd, RAW_GETBIND, &rq) < 0) {
		close(fd);
		return 1;
	}

	close(fd);
	*majdev = rq.block_major;
	*mindev = rq.block_minor;
	return 0;
}

#ifdef O_NOATIME
#define FIO_O_NOATIME	O_NOATIME
#else
#define FIO_O_NOATIME	0
#endif

#ifdef O_ATOMIC
#define OS_O_ATOMIC	O_ATOMIC
#else
#define OS_O_ATOMIC	040000000
#endif

#ifdef MADV_REMOVE
#define FIO_MADV_FREE	MADV_REMOVE
#endif

#define fio_swap16(x)	__bswap_16(x)
#define fio_swap32(x)	__bswap_32(x)
#define fio_swap64(x)	__bswap_64(x)

#define CACHE_LINE_FILE	\
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void)
{
	char size[32];
	int fd, ret;

	fd = open(CACHE_LINE_FILE, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, size, sizeof(size));

	close(fd);

	if (ret <= 0)
		return -1;
	else
		return atoi(size);
}

static inline unsigned long long get_fs_size(const char *path)
{
	unsigned long long ret;
	struct statfs s;

	if (statfs(path, &s) < 0)
		return -1ULL;

	ret = s.f_bsize;
	ret *= (unsigned long long) s.f_bfree;
	return ret;
}

static inline int os_trim(int fd, unsigned long long start,
			  unsigned long long len)
{
	uint64_t range[2];

	range[0] = start;
	range[1] = len;

	if (!ioctl(fd, BLKDISCARD, range))
		return 0;

	return errno;
}

#ifdef CONFIG_SCHED_IDLE
static inline int fio_set_sched_idle(void)
{
	struct sched_param p = { .sched_priority = 0, };
	return sched_setscheduler(gettid(), SCHED_IDLE, &p);
}
#endif

#endif
