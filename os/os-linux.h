#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <linux/raw.h>
#include <linux/major.h>

#include "indirect.h"

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
#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_POSIXAIO_FSYNC

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
#define fio_setaffinity(td)		\
	sched_setaffinity((td)->pid, sizeof((td)->o.cpumask), &(td)->o.cpumask)
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), sizeof(cpu_set_t), (ptr))
#else
#define fio_setaffinity(td)		\
	sched_setaffinity((td)->pid, &(td)->o.cpumask)
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), (ptr))
#endif

#define fio_cpu_clear(mask, cpu)	CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)		CPU_SET((cpu), (mask))

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

static inline int blockdev_invalidate_cache(int fd)
{
	return ioctl(fd, BLKFLSBUF);
}

static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	if (!ioctl(fd, BLKGETSIZE64, bytes))
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

#endif
