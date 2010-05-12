#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#include <errno.h>
#include <sys/sysctl.h>

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_USE_GENERIC_RAND

#define OS_MAP_ANON		MAP_ANON

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
