#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/unistd.h>

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

#define OS_MAP_ANON		(MAP_ANONYMOUS)

typedef cpu_set_t os_cpu_mask_t;
typedef struct drand48_data os_random_state_t;

/*
 * we want fadvise64 really, but it's so tangled... later
 */
#define fadvise(fd, off, len, advice)	\
	posix_fadvise((fd), (off_t)(off), (len), (advice))

#define fio_setaffinity(td)		\
	sched_setaffinity((td)->pid, sizeof((td)->cpumask), &(td)->cpumask)
#define fio_getaffinity(pid, ptr)	\
	sched_getaffinity((pid), sizeof(cpu_set_t), (ptr))

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
			 size_t len, unsigned long flags)
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

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_CLASS_SHIFT	13

#ifndef BLKGETSIZE64
#define BLKGETSIZE64	_IOR(0x12,114,size_t)
#endif

#ifndef BLKFLSBUF
#define BLKFLSBUF	_IO(0x12,97)
#endif

static inline int blockdev_invalidate_cache(int fd)
{
	if (!ioctl(fd, BLKFLSBUF))
		return 0;

	return errno;
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

static inline double os_random_double(os_random_state_t *rs)
{
	double val;

	drand48_r(rs, &val);
	return val;
}

#endif
