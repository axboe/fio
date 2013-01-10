#ifndef FIO_OS_AIX_H
#define FIO_OS_AIX_H

#define	FIO_OS	os_aix

#include <errno.h>
#include <unistd.h>
#include <sys/devinfo.h>
#include <sys/ioctl.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE

#define FIO_HAVE_PSHARED_MUTEX

#define OS_MAP_ANON		MAP_ANON
#define OS_MSG_DONTWAIT		0

#if BYTE_ORDER == BIG_ENDIAN
#define FIO_BIG_ENDIAN
#else
#define FIO_LITTLE_ENDIAN
#endif

#define FIO_USE_GENERIC_SWAP

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return EINVAL;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct devinfo info;

	if (!ioctl(f->fd, IOCINFO, &info)) {
        	*bytes = (unsigned long long)info.un.scdk.numblks *
				info.un.scdk.blksize;
		return 0;
	}

	return errno;
}

static inline unsigned long long os_phys_mem(void)
{
	long mem = sysconf(_SC_AIX_REALMEM);

	if (mem == -1)
		return 0;

	return (unsigned long long) mem * 1024;
}

#endif
