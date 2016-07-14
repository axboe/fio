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

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_GETTID

#undef	FIO_HAVE_CPU_AFFINITY	/* XXX notyet */

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

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
	return EINVAL;
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

#endif
