#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <asm/unistd.h>

#define FIO_HAVE_LIBAIO
#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_FADVISE
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_SGIO
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_SPLICE

#define OS_MAP_ANON		(MAP_ANONYMOUS)

typedef cpu_set_t os_cpu_mask_t;

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

static _syscall6(int, sys_splice, int, fdin, loff_t *, off_in, int, fdout, loff_t *, off_out, size_t, len, unsigned int, flags);
static _syscall4(int, sys_vmsplice, int, fd, const struct iovec *, iov, unsigned long, nr_segs, unsigned int, flags);
static _syscall4(int, sys_tee, int, fdin, int, fdout, size_t, len, unsigned int, flags);

static inline int splice(int fdin, loff_t *off_in, int fdout, loff_t *off_out,
			 size_t len, unsigned long flags)
{
	return sys_splice(fdin, off_in, fdout, off_out, len, flags);
}

static inline int tee(int fdin, int fdout, size_t len, unsigned int flags)
{
	return sys_tee(fdin, fdout, len, flags);
}

static inline int vmsplice(int fd, const struct iovec *iov,
			   unsigned long nr_segs, unsigned int flags)
{
	return sys_vmsplice(fd, iov, nr_segs, flags);
}

#define SPLICE_F_MOVE	(0x01)	/* move pages instead of copying */
#define SPLICE_F_NONBLOCK (0x02) /* don't block on the pipe splicing (but */
				 /* we may still block on the fd we splice */
				 /* from/to, of course */
#define SPLICE_F_MORE	(0x04)	/* expect more data */
#define SPLICE_F_GIFT   (0x08)  /* pages passed in are a gift */

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

static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	if (!ioctl(fd, BLKGETSIZE64, bytes))
		return 0;

	return errno;
}

#endif
