#ifndef FIO_OS_APPLE_H
#define FIO_OS_APPLE_H

#define	FIO_OS	os_mac

#include <errno.h>
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <mach/mach_init.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#include "../file.h"

#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID
#define FIO_HAVE_CHARDEV_SIZE

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	OSSwapInt16(x)
#define fio_swap32(x)	OSSwapInt32(x)
#define fio_swap64(x)	OSSwapInt64(x)

/*
 * OSX has a pitifully small shared memory segment by default,
 * so default to a lower number of max jobs supported
 */
#define FIO_MAX_JOBS		128

typedef off_t off64_t;

typedef unsigned int clockid_t;

#define FIO_OS_DIRECTIO
static inline int fio_set_odirect(int fd)
{
	if (fcntl(fd, F_NOCACHE, 1) == -1)
		return errno;
	return 0;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	uint32_t block_size;
	uint64_t block_count;

	if (ioctl(f->fd, DKIOCGETBLOCKCOUNT, &block_count) == -1)
		return errno;
	if (ioctl(f->fd, DKIOCGETBLOCKSIZE, &block_size) == -1)
		return errno;

	*bytes = block_size;
	*bytes *= block_count;
	return 0;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	/*
	 * Could be a raw block device, this is better than just assuming
	 * we can't get the size at all.
	 */
	if (!blockdev_size(f, bytes))
		return 0;

	*bytes = -1ULL;
	return 0;
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
	return mach_thread_self();
}

/*
 * For some reason, there's no header definition for fdatasync(), even
 * if it exists.
 */
extern int fdatasync(int fd);

#endif
