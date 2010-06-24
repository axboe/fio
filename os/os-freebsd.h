#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#include <errno.h>
#include <sys/sysctl.h>
#include <sys/disk.h>

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_HAVE_CHARDEV_SIZE

#define OS_MAP_ANON		MAP_ANON

typedef off_t off64_t;

static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	off_t size;

	if (!ioctl(fd, DIOCGMEDIASIZE, &size)) {
		*bytes = size;
		return 0;
	}

	*bytes = 0;
	return errno;
}

static inline int chardev_size(int fd, unsigned long long *bytes)
{
	return blockdev_size(fd, bytes);
}

static inline int blockdev_invalidate_cache(int fd)
{
	return EINVAL;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM };
	unsigned long long mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
