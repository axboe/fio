#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#define	FIO_OS	os_freebsd

#include <errno.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include <sys/thr.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_GETTID
#define FIO_HAVE_CPU_AFFINITY

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

typedef cpuset_t os_cpu_mask_t;

#define fio_cpu_clear(mask, cpu)        (void) CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)          (void) CPU_SET((cpu), (mask))
#define fio_cpu_isset(mask, cpu)	CPU_ISSET((cpu), (mask))
#define fio_cpu_count(mask)		CPU_COUNT((mask))

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
        CPU_ZERO(mask);
        return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
        return 0;
}

static inline int fio_setaffinity(int pid, os_cpu_mask_t cpumask)
{
	return cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, pid, sizeof(cpumask), &cpumask);
}

static inline int fio_getaffinity(int pid, os_cpu_mask_t *cpumask)
{
	return cpuset_getaffinity(CPU_LEVEL_WHICH, CPU_WHICH_PID, pid, sizeof(cpumask), cpumask);
}

#define FIO_MAX_CPUS                    CPU_SETSIZE

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
