#ifndef FIO_OS_LINUX_H
#define FIO_OS_LINUX_H

#include <sys/ioctl.h>

#define FIO_HAVE_LIBAIO
#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_FADVISE
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_SGIO

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
