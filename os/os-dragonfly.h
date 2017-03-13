#ifndef FIO_OS_DRAGONFLY_H
#define FIO_OS_DRAGONFLY_H

#define	FIO_OS	os_dragonfly

#include <errno.h>
#include <unistd.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/statvfs.h>
#include <sys/diskslice.h>
#include <sys/ioctl_compat.h>
#include <sys/usched.h>
#include <sys/resource.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_GETTID
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_SHM_ATTACH_REMOVED

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

/* This is supposed to equal (sizeof(cpumask_t)*8) */
#define FIO_MAX_CPUS	SMP_MAXCPU

typedef off_t off64_t;
typedef cpumask_t os_cpu_mask_t;

/*
 * These macros are copied from sys/cpu/x86_64/include/types.h.
 * It's okay to copy from arch dependent header because x86_64 is the only
 * supported arch, and no other arch is going to be supported any time soon.
 *
 * These are supposed to be able to be included from userspace by defining
 * _KERNEL_STRUCTURES, however this scheme is badly broken that enabling it
 * causes compile-time conflicts with other headers. Although the current
 * upstream code no longer requires _KERNEL_STRUCTURES, they should be kept
 * here for compatibility with older versions.
 */
#ifndef CPUMASK_SIMPLE
#define CPUMASK_SIMPLE(cpu)		((uint64_t)1 << (cpu))
#define CPUMASK_TESTBIT(val, i)		((val).ary[((i) >> 6) & 3] & \
					 CPUMASK_SIMPLE((i) & 63))
#define CPUMASK_ORBIT(mask, i)		((mask).ary[((i) >> 6) & 3] |= \
					 CPUMASK_SIMPLE((i) & 63))
#define CPUMASK_NANDBIT(mask, i)	((mask).ary[((i) >> 6) & 3] &= \
					 ~CPUMASK_SIMPLE((i) & 63))
#define CPUMASK_ASSZERO(mask)		do {				\
					(mask).ary[0] = 0;		\
					(mask).ary[1] = 0;		\
					(mask).ary[2] = 0;		\
					(mask).ary[3] = 0;		\
					} while(0)
#endif

/*
 * Define USCHED_GET_CPUMASK as the macro didn't exist until release 4.5.
 * usched_set(2) returns EINVAL if the kernel doesn't support it.
 *
 * Also note usched_set(2) works only for the current thread regardless of
 * the command type. It doesn't work against another thread regardless of
 * a caller's privilege. A caller would generally specify 0 for pid for the
 * current thread though that's the only choice. See BUGS in usched_set(2).
 */
#ifndef USCHED_GET_CPUMASK
#define USCHED_GET_CPUMASK	5
#endif

/* No CPU_COUNT(), but use the default function defined in os/os.h */
#define fio_cpu_count(mask)             CPU_COUNT((mask))

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
	CPUMASK_ASSZERO(*mask);
	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return 0;
}

static inline void fio_cpu_clear(os_cpu_mask_t *mask, int cpu)
{
	CPUMASK_NANDBIT(*mask, cpu);
}

static inline void fio_cpu_set(os_cpu_mask_t *mask, int cpu)
{
	CPUMASK_ORBIT(*mask, cpu);
}

static inline int fio_cpu_isset(os_cpu_mask_t *mask, int cpu)
{
	if (CPUMASK_TESTBIT(*mask, cpu))
		return 1;

	return 0;
}

static inline int fio_setaffinity(int pid, os_cpu_mask_t mask)
{
	int i, firstcall = 1;

	/* 0 for the current thread, see BUGS in usched_set(2) */
	pid = 0;

	for (i = 0; i < FIO_MAX_CPUS; i++) {
		if (!CPUMASK_TESTBIT(mask, i))
			continue;
		if (firstcall) {
			if (usched_set(pid, USCHED_SET_CPU, &i, sizeof(int)))
				return -1;
			firstcall = 0;
		} else {
			if (usched_set(pid, USCHED_ADD_CPU, &i, sizeof(int)))
				return -1;
		}
	}

	return 0;
}

static inline int fio_getaffinity(int pid, os_cpu_mask_t *mask)
{
	/* 0 for the current thread, see BUGS in usched_set(2) */
	pid = 0;

	if (usched_set(pid, USCHED_GET_CPUMASK, mask, sizeof(*mask)))
		return -1;

	return 0;
}

/* fio code is Linux based, so rename macros to Linux style */
#define IOPRIO_WHO_PROCESS	PRIO_PROCESS
#define IOPRIO_WHO_PGRP		PRIO_PGRP
#define IOPRIO_WHO_USER		PRIO_USER

#define IOPRIO_MIN_PRIO		1	/* lowest priority */
#define IOPRIO_MAX_PRIO		10	/* highest priority */

/*
 * Prototypes declared in sys/sys/resource.h are preventing from defining
 * ioprio_set() with 4 arguments, so define fio's ioprio_set() as a macro.
 * Note that there is no idea of class within ioprio_set(2) unlike Linux.
 */
#define ioprio_set(which, who, ioprio_class, ioprio)	\
	ioprio_set(which, who, ioprio)

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct partinfo pi;

	if (!ioctl(f->fd, DIOCGPART, &pi)) {
		*bytes = (unsigned long long) pi.media_size;
		return 0;
	}

	*bytes = 0;
	return errno;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	return blockdev_size(f, bytes);
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM };
	uint64_t mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

static inline int gettid(void)
{
	return (int) lwp_gettid();
}

static inline unsigned long long get_fs_free_size(const char *path)
{
	unsigned long long ret;
	struct statvfs s;

	if (statvfs(path, &s) < 0)
		return -1ULL;

	ret = s.f_frsize;
	ret *= (unsigned long long) s.f_bfree;
	return ret;
}

static inline int os_trim(int fd, unsigned long long start,
			  unsigned long long len)
{
	off_t range[2];

	range[0] = start;
	range[1] = len;

	if (!ioctl(fd, IOCTLTRIM, range))
		return 0;

	return errno;
}

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

static inline int shm_attach_to_open_removed(void)
{
	int x;
	size_t len = sizeof(x);

	if (sysctlbyname("kern.ipc.shm_allow_removed", &x, &len, NULL, 0) < 0)
		return 0;

	return x > 0 ? 1 : 0;
}

#endif
