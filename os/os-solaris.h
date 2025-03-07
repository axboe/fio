#ifndef FIO_OS_SOLARIS_H
#define FIO_OS_SOLARIS_H

#define	FIO_OS	os_solaris

#include <errno.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/pset.h>
#include <sys/mman.h>
#include <sys/dkio.h>
#include <sys/byteorder.h>
#include <sys/statvfs.h>
#include <pthread.h>

#include "../file.h"
#include "../lib/types.h"

#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_HAVE_FS_STAT
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID

#define OS_MAP_ANON		MAP_ANON
#define OS_RAND_MAX		2147483648UL

#define fio_swap16(x)	BSWAP_16(x)
#define fio_swap32(x)	BSWAP_32(x)
#define fio_swap64(x)	BSWAP_64(x)

struct solaris_rand_seed {
	unsigned short r[3];
};

#ifndef POSIX_MADV_SEQUENTIAL
#define posix_madvise	madvise
#define POSIX_MADV_SEQUENTIAL	MADV_SEQUENTIAL
#define POSIX_MADV_DONTNEED	MADV_DONTNEED
#define POSIX_MADV_RANDOM	MADV_RANDOM
#endif

#define os_ctime_r(x, y, z)     ctime_r((x), (y), (z))
#define FIO_OS_HAS_CTIME_R

#ifdef CONFIG_PTHREAD_GETAFFINITY
#define FIO_HAVE_GET_THREAD_AFFINITY
#define fio_get_thread_affinity(mask)	\
	pthread_getaffinity_np(pthread_self(), sizeof(mask), &(mask))
#endif

typedef psetid_t os_cpu_mask_t;

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct dk_minfo info;

	*bytes = 0;

	if (ioctl(f->fd, DKIOCGMEDIAINFO, &info) < 0)
		return errno;

	*bytes = info.dki_lbsize * info.dki_capacity;
	return 0;
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	long pagesize, pages;

	pagesize = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (pages == -1 || pagesize == -1)
		return 0;

	return (unsigned long long) pages * (unsigned long long) pagesize;
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

#define FIO_OS_DIRECTIO
extern int directio(int, int);
static inline int fio_set_odirect(struct fio_file *f)
{
	if (directio(f->fd, DIRECTIO_ON) < 0)
		return errno;

	return 0;
}

/*
 * pset binding hooks for fio
 */
#define fio_setaffinity(pid, cpumask)		\
	pset_bind((cpumask), P_LWPID, (pid), NULL)
#define fio_getaffinity(pid, ptr)	({ 0; })

#define fio_cpu_clear(mask, cpu)	pset_assign(PS_NONE, (cpu), NULL)
#define fio_cpu_set(mask, cpu)		pset_assign(*(mask), (cpu), NULL)

static inline bool fio_cpu_isset(os_cpu_mask_t *mask, int cpu)
{
	const unsigned int max_cpus = sysconf(_SC_NPROCESSORS_CONF);
	unsigned int num_cpus;
	processorid_t *cpus;
	bool ret;
	int i;

	cpus = malloc(sizeof(*cpus) * max_cpus);

	if (pset_info(*mask, NULL, &num_cpus, cpus) < 0) {
		free(cpus);
		return false;
	}

	ret = false;
	for (i = 0; i < num_cpus; i++) {
		if (cpus[i] == cpu) {
			ret = true;
			break;
		}
	}

	free(cpus);
	return ret;
}

static inline int fio_cpu_count(os_cpu_mask_t *mask)
{
	unsigned int num_cpus;

	if (pset_info(*mask, NULL, &num_cpus, NULL) < 0)
		return 0;

	return num_cpus;
}

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
	if (pset_create(mask) < 0)
		return -1;

	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	if (pset_destroy(*mask) < 0)
		return -1;

	return 0;
}

#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return pthread_self();
}
#endif

/*
 * Should be enough, not aware of what (if any) restrictions Solaris has
 */
#define FIO_MAX_CPUS			16384

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
