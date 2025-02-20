#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#ifdef __ANDROID__
#define FIO_OS  os_android
#else
#define	FIO_OS	os_linux
#endif

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <linux/unistd.h>
#include <linux/major.h>
#include <linux/fs.h>
#include <scsi/sg.h>
#include <asm/byteorder.h>
#ifdef __ANDROID__
#include "os-ashmem.h"
#define FIO_NO_HAVE_SHM_H
#endif

#ifdef ARCH_HAVE_CRC_CRYPTO
#include <sys/auxv.h>
#ifndef HWCAP_PMULL
#define HWCAP_PMULL             (1 << 4)
#endif /* HWCAP_PMULL */
#ifndef HWCAP_CRC32
#define HWCAP_CRC32             (1 << 7)
#endif /* HWCAP_CRC32 */
#endif /* ARCH_HAVE_CRC_CRYPTO */

#include "./os-linux-syscall.h"
#include "../file.h"

#ifndef __has_builtin         // Optional of course.
  #define __has_builtin(x) 0  // Compatibility with non-clang compilers.
#endif

#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_SGIO
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_IOPRIO_CLASS
#define FIO_HAVE_IOSCHED_SWITCH
#define FIO_HAVE_ODIRECT
#define FIO_HAVE_HUGETLB
#define FIO_HAVE_BLKTRACE
#define FIO_HAVE_CL_SIZE
#define FIO_HAVE_CGROUPS
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_GETTID
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_BYTEORDER_FUNCS
#define FIO_HAVE_PWRITEV2
#define FIO_HAVE_SHM_ATTACH_REMOVED
#define FIO_HAVE_RWF_ATOMIC

#ifdef MAP_HUGETLB
#define FIO_HAVE_MMAP_HUGE
#endif

#define OS_MAP_ANON		MAP_ANONYMOUS

#define FIO_EXT_ENG_DIR	"/usr/local/lib/fio"

typedef cpu_set_t os_cpu_mask_t;

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

#ifdef CONFIG_PTHREAD_GETAFFINITY
#define FIO_HAVE_GET_THREAD_AFFINITY
#define fio_get_thread_affinity(mask)	\
	pthread_getaffinity_np(pthread_self(), sizeof(mask), &(mask))
#endif

#define fio_cpu_clear(mask, cpu)	CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)		CPU_SET((cpu), (mask))
#define fio_cpu_isset(mask, cpu)	(CPU_ISSET((cpu), (mask)) != 0)
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

#define IOPRIO_HINT_BITS	10
#define IOPRIO_HINT_SHIFT	3

#define IOPRIO_MIN_PRIO		0	/* highest priority */
#define IOPRIO_MAX_PRIO		7	/* lowest priority */

#define IOPRIO_MIN_PRIO_CLASS	0
#define IOPRIO_MAX_PRIO_CLASS	3

#define IOPRIO_MIN_PRIO_HINT	0
#define IOPRIO_MAX_PRIO_HINT	((1 << IOPRIO_HINT_BITS) - 1)

#define ioprio_class(ioprio)	((ioprio) >> IOPRIO_CLASS_SHIFT)
#define ioprio(ioprio)		((ioprio) & IOPRIO_MAX_PRIO)
#define ioprio_hint(ioprio)	\
	(((ioprio) >> IOPRIO_HINT_SHIFT) & IOPRIO_MAX_PRIO_HINT)

static inline int ioprio_value(int ioprio_class, int ioprio, int ioprio_hint)
{
	/*
	 * If no class is set, assume BE
	 */
        if (!ioprio_class)
                ioprio_class = IOPRIO_CLASS_BE;

	return (ioprio_class << IOPRIO_CLASS_SHIFT) |
		(ioprio_hint << IOPRIO_HINT_SHIFT) |
		ioprio;
}

static inline bool ioprio_value_is_class_rt(unsigned int priority)
{
	return ioprio_class(priority) == IOPRIO_CLASS_RT;
}

static inline int ioprio_set(int which, int who, int ioprio_class, int ioprio,
			     int ioprio_hint)
{
	return syscall(__NR_ioprio_set, which, who,
		       ioprio_value(ioprio_class, ioprio, ioprio_hint));
}

#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return syscall(__NR_gettid);
}
#endif

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

#ifdef O_NOATIME
#define FIO_O_NOATIME	O_NOATIME
#else
#define FIO_O_NOATIME	0
#endif

#ifdef MADV_REMOVE
#define FIO_MADV_FREE	MADV_REMOVE
#endif

/* Check for GCC or Clang byte swap intrinsics */
#if (__has_builtin(__builtin_bswap16) && __has_builtin(__builtin_bswap32) \
     && __has_builtin(__builtin_bswap64)) || (__GNUC__ > 4 \
     || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) /* fio_swapN */
#define fio_swap16(x)	__builtin_bswap16(x)
#define fio_swap32(x)	__builtin_bswap32(x)
#define fio_swap64(x)	__builtin_bswap64(x)
#else
#include <byteswap.h>
#define fio_swap16(x)	bswap_16(x)
#define fio_swap32(x)	bswap_32(x)
#define fio_swap64(x)	bswap_64(x)
#endif /* fio_swapN */

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

static inline unsigned long long get_fs_free_size(const char *path)
{
	unsigned long long ret;
	struct statfs s;

	if (statfs(path, &s) < 0)
		return -1ULL;

	ret = s.f_bsize;
	ret *= (unsigned long long) s.f_bfree;
	return ret;
}

static inline int os_trim(struct fio_file *f, unsigned long long start,
			  unsigned long long len)
{
	uint64_t range[2];

	range[0] = start;
	range[1] = len;

	if (!ioctl(f->fd, BLKDISCARD, range))
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

#ifndef F_GET_RW_HINT
#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE	1024
#endif
#define F_GET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 14)
#endif

#ifndef RWH_WRITE_LIFE_NONE
#define RWH_WRITE_LIFE_NOT_SET	0
#define RWH_WRITE_LIFE_NONE	1
#define RWH_WRITE_LIFE_SHORT	2
#define RWH_WRITE_LIFE_MEDIUM	3
#define RWH_WRITE_LIFE_LONG	4
#define RWH_WRITE_LIFE_EXTREME	5
#endif

#define FIO_HAVE_WRITE_HINT

#ifndef RWF_HIPRI
#define RWF_HIPRI	0x00000001
#endif
#ifndef RWF_DSYNC
#define RWF_DSYNC	0x00000002
#endif
#ifndef RWF_SYNC
#define RWF_SYNC	0x00000004
#endif
#ifndef RWF_NOWAIT
#define RWF_NOWAIT	0x00000008
#endif

#ifndef RWF_ATOMIC
#define RWF_ATOMIC	0x00000040
#endif

#ifndef RWF_DONTCACHE
#define RWF_DONTCACHE	0x00000080
#endif

#ifndef RWF_WRITE_LIFE_SHIFT
#define RWF_WRITE_LIFE_SHIFT		4
#define RWF_WRITE_LIFE_SHORT		(1 << RWF_WRITE_LIFE_SHIFT)
#define RWF_WRITE_LIFE_MEDIUM		(2 << RWF_WRITE_LIFE_SHIFT)
#define RWF_WRITE_LIFE_LONG		(3 << RWF_WRITE_LIFE_SHIFT)
#define RWF_WRITE_LIFE_EXTREME		(4 << RWF_WRITE_LIFE_SHIFT)
#endif

#ifndef CONFIG_PWRITEV2
#ifdef __NR_preadv2
static inline void make_pos_h_l(unsigned long *pos_h, unsigned long *pos_l,
				off_t offset)
{
#if BITS_PER_LONG == 64
	*pos_l = offset;
	*pos_h = 0;
#else
	*pos_l = offset & 0xffffffff;
	*pos_h = ((uint64_t) offset) >> 32;
#endif
}
static inline ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
			      off_t offset, unsigned int flags)
{
	unsigned long pos_l, pos_h;

	make_pos_h_l(&pos_h, &pos_l, offset);
	return syscall(__NR_preadv2, fd, iov, iovcnt, pos_l, pos_h, flags);
}
static inline ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
			       off_t offset, unsigned int flags)
{
	unsigned long pos_l, pos_h;

	make_pos_h_l(&pos_h, &pos_l, offset);
	return syscall(__NR_pwritev2, fd, iov, iovcnt, pos_l, pos_h, flags);
}
#else
static inline ssize_t preadv2(int fd, const struct iovec *iov, int iovcnt,
			      off_t offset, unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
static inline ssize_t pwritev2(int fd, const struct iovec *iov, int iovcnt,
			       off_t offset, unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif /* __NR_preadv2 */
#endif /* CONFIG_PWRITEV2 */

static inline int shm_attach_to_open_removed(void)
{
	return 1;
}

#ifdef CONFIG_LINUX_FALLOCATE
#define FIO_HAVE_NATIVE_FALLOCATE
static inline bool fio_fallocate(struct fio_file *f, uint64_t offset,
				 uint64_t len)
{
	int ret;
	ret = fallocate(f->fd, 0, offset, len);
	if (ret == 0)
		return true;

	/* Work around buggy old glibc versions... */
	if (ret > 0)
		errno = ret;

	return false;
}
#endif

#define FIO_HAVE_CPU_HAS
static inline bool os_cpu_has(cpu_features feature)
{
	bool have_feature;
	unsigned long fio_unused hwcap;

	switch (feature) {
#ifdef ARCH_HAVE_CRC_CRYPTO
	case CPU_ARM64_CRC32C:
		hwcap = getauxval(AT_HWCAP);
		have_feature = (hwcap & (HWCAP_PMULL | HWCAP_CRC32)) ==
			       (HWCAP_PMULL | HWCAP_CRC32);
		break;
#endif
	default:
		have_feature = false;
	}

	return have_feature;
}

#endif
