#ifndef FIO_OS_HPUX_H
#define FIO_OS_HPUX_H

#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/fadvise.h>
#include <sys/mman.h>
#include <sys/mpctl.h>
#include <sys/scsi.h>

#include "../file.h"

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_HAVE_CLOCK_MONOTONIC
#define FIO_HAVE_PSHARED_MUTEX
#define FIO_HAVE_FADVISE

#define OS_MAP_ANON		MAP_ANONYMOUS
#define OS_MSG_DONTWAIT		0

#define POSIX_MADV_DONTNEED	MADV_DONTNEED
#define POSIX_MADV_SEQUENTIAL	MADV_SEQUENTIAL
#define POSIX_MADV_RANDOM	MADV_RANDOM
#define posix_madvise(ptr, sz, hint)	madvise((ptr), (sz), (hint))

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return EINVAL;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct capacity cap;

	if (!ioctl(f->fd, SIOC_CAPACITY, &cap) == -1) {
		*bytes = cap.lba * cap.blksz;
		return 0;
	}

	*bytes = 0;
	return errno;
}

static inline unsigned long long os_phys_mem(void)
{
#if 0
	long mem = sysconf(_SC_AIX_REALMEM);

	if (mem == -1)
		return 0;

	return (unsigned long long) mem * 1024;
#else
	return 0;
#endif
}

#define FIO_HAVE_CPU_ONLINE_SYSCONF

static inline unsigned int cpus_online(void)
{
	return mpctl(MPC_GETNUMSPUS, 0, NULL);
}

#endif
