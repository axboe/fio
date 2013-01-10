#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#define	FIO_OS	os_freebsd

#include <errno.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include <sys/thr.h>
#include <sys/endian.h>
#include <sys/socket.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_GETTID

#define OS_MAP_ANON		MAP_ANON

#if BYTE_ORDER == LITTLE_ENDIAN
#define FIO_LITTLE_ENDIAN
#else
#define FIO_BIG_ENDIAN
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	off_t size;

	if (!ioctl(f->fd, DIOCGMEDIASIZE, &size)) {
		*bytes = size;
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

static inline int gettid(void)
{
	long lwpid;

	thr_self(&lwpid);
	return (int) lwpid;
}

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
