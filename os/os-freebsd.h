#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#define	FIO_OS	os_freebsd

#include <errno.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include <sys/endian.h>
#include <sys/thr.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/cpuset.h>
#include <sys/statvfs.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_GETTID
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_SHM_ATTACH_REMOVED

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef cpuset_t os_cpu_mask_t;

#define fio_cpu_clear(mask, cpu)        (void) CPU_CLR((cpu), (mask))
#define fio_cpu_set(mask, cpu)          (void) CPU_SET((cpu), (mask))
#define fio_cpu_isset(mask, cpu)	(CPU_ISSET((cpu), (mask)) != 0)
#define fio_cpu_count(mask)		CPU_COUNT((mask))

#ifdef CONFIG_PTHREAD_GETAFFINITY
#define FIO_HAVE_GET_THREAD_AFFINITY
#define fio_get_thread_affinity(mask)	\
	pthread_getaffinity_np(pthread_self(), sizeof(mask), &(mask))
#endif

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
	return ENOTSUP;
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

static inline int os_trim(struct fio_file *f, unsigned long long start,
			  unsigned long long len)
{
	off_t range[2];

	range[0] = start;
	range[1] = len;

	if (!ioctl(f->fd, DIOCGDELETE, range))
		return 0;

	return errno;
}

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

static inline int shm_attach_to_open_removed(void)
{
	int x;
	size_t len = sizeof(x);

	if (sysctlbyname("kern.ipc.shm_allow_removed", &x, &len, NULL, 0) < 0)
		return 0;

	return x > 0 ? 1 : 0;
}

#endif
