#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#define	FIO_OS	os_linux

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <linux/unistd.h>
#include <linux/raw.h>
#include <linux/major.h>
#include <endian.h>

#include "indirect.h"
#include "binject.h"
#include "../file.h"

#define FIO_HAVE_LIBAIO
#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_FADVISE
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_SGIO
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_SPLICE
#define FIO_HAVE_IOSCHED_SWITCH
#define FIO_HAVE_ODIRECT
#define FIO_HAVE_HUGETLB
#define FIO_HAVE_RAWBIND
#define FIO_HAVE_BLKTRACE
#define FIO_HAVE_STRSEP
#define FIO_HAVE_POSIXAIO_FSYNC
#define FIO_HAVE_PSHARED_MUTEX
#define FIO_HAVE_CL_SIZE
#define FIO_HAVE_CGROUPS
#define FIO_HAVE_FDATASYNC
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_BINJECT
#define FIO_HAVE_CLOCK_MONOTONIC
#define FIO_HAVE_GETTID
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_E4_ENG

/*
 * Can only enable this for newer glibcs, or the header and defines are
 * missing
 */
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 6
#define FIO_HAVE_FALLOCATE
#endif
#if __GLIBC__ >= 2 && __GLIBC_MINOR__ >= 8
#define FIO_HAVE_LINUX_FALLOCATE
#endif

#ifdef FIO_HAVE_LINUX_FALLOCATE
#define FIO_HAVE_FALLOC_ENG
#endif

#ifdef SYNC_FILE_RANGE_WAIT_BEFORE
#define FIO_HAVE_SYNC_FILE_RANGE
#endif

#define OS_MAP_ANON		MAP_ANONYMOUS

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

typedef cpu_set_t os_cpu_mask_t;

typedef struct drand48_data os_random_state_t;

/*
 * we want fadvise64 really, but it's so tangled... later
 */
#ifdef FIO_HAVE_FADVISE
#define fadvise(fd, off, len, advice)	\
	posix_fadvise((fd), (off_t)(off), (len), (advice))
#endif

/*
 * If you are on an ancient glibc (2.3.2), then define GLIBC_2_3_2 if you want
 * the affinity helpers to work.
 */
#ifndef GLIBC_2_3_2
#define fio_setaffinity(pid, cpumask)		\
	sched_setaffinity((pid), sizeof(cpumask), &(cpumask))
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), sizeof(cpu_set_t), (ptr))
#else
#define fio_setaffinity(pid, cpumask)	\
	sched_setaffinity((pid), &(cpumask))
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), (ptr))
#endif

#define fio_cpu_clear(mask, cpu)	(void) CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)		(void) CPU_SET((cpu), (mask))

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

static inline int ioprio_set(int which, int who, int ioprio)
{
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

static inline int gettid(void)
{
	return syscall(__NR_gettid);
}

/*
 * Just check for SPLICE_F_MOVE, if that isn't there, assume the others
 * aren't either.
 */
#ifndef SPLICE_F_MOVE
#define SPLICE_F_MOVE	(0x01)	/* move pages instead of copying */
#define SPLICE_F_NONBLOCK (0x02) /* don't block on the pipe splicing (but */
				 /* we may still block on the fd we splice */
				 /* from/to, of course */
#define SPLICE_F_MORE	(0x04)	/* expect more data */
#define SPLICE_F_GIFT   (0x08)  /* pages passed in are a gift */

static inline int splice(int fdin, loff_t *off_in, int fdout, loff_t *off_out,
			 size_t len, unsigned int flags)
{
	return syscall(__NR_sys_splice, fdin, off_in, fdout, off_out, len, flags);
}

static inline int tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	return syscall(__NR_sys_tee, fdin, fdout, len, flags);
}

static inline int vmsplice(int fd, const struct iovec *iov,
			   unsigned long nr_segs, unsigned int flags)
{
	return syscall(__NR_sys_vmsplice, fd, iov, nr_segs, flags);
}
#endif

#define SPLICE_DEF_SIZE	(64*1024)

#ifdef FIO_HAVE_SYSLET

struct syslet_uatom;
struct async_head_user;

/*
 * syslet stuff
 */
static inline struct syslet_uatom *
async_exec(struct syslet_uatom *atom, struct async_head_user *ahu)
{
	return (struct syslet_uatom *) syscall(__NR_async_exec, atom, ahu);
}

static inline long
async_wait(unsigned long min_wait_events, unsigned long user_ring_idx,
	   struct async_head_user *ahu)
{
	return syscall(__NR_async_wait, min_wait_events,
			user_ring_idx, ahu);
}

static inline long async_thread(void *event, struct async_head_user *ahu)
{
	return syscall(__NR_async_thread, event, ahu);
}

static inline long umem_add(unsigned long *uptr, unsigned long inc)
{
	return syscall(__NR_umem_add, uptr, inc);
}
#endif /* FIO_HAVE_SYSLET */

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

#ifdef MADV_REMOVE
#define FIO_MADV_FREE	MADV_REMOVE
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define FIO_LITTLE_ENDIAN
#elif __BYTE_ORDER == __BIG_ENDIAN
#define FIO_BIG_ENDIAN
#else
#error "Unknown endianness"
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

#endif
