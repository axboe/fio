#ifndef FIO_OS_SOLARIS_H
#define FIO_OS_SOLARIS_H

#define	FIO_OS	os_solaris

#include <errno.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/pset.h>
#include <sys/mman.h>
#include <sys/dkio.h>
#include <sys/byteorder.h>

#include "../file.h"

#define FIO_HAVE_SOLARISAIO
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_PSHARED_MUTEX
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID

#define OS_MAP_ANON		MAP_ANON
#define OS_RAND_MAX		2147483648UL

#if defined(_BIG_ENDIAN)
#define FIO_BIG_ENDIAN
#else
#define FIO_LITTLE_ENDIAN
#endif

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

typedef psetid_t os_cpu_mask_t;
typedef struct solaris_rand_seed os_random_state_t;

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
	return 0;
}

static inline unsigned long long os_phys_mem(void)
{
	return 0;
}

static inline void os_random_seed(unsigned long seed, os_random_state_t *rs)
{
	rs->r[0] = seed & 0xffff;
	seed >>= 16;
	rs->r[1] = seed & 0xffff;
	seed >>= 16;
	rs->r[2] = seed & 0xffff;
	seed48(rs->r);
}

static inline long os_random_long(os_random_state_t *rs)
{
	return nrand48(rs->r);
}

#define FIO_OS_DIRECTIO
extern int directio(int, int);
static inline int fio_set_odirect(int fd)
{
	if (directio(fd, DIRECTIO_ON) < 0)
		return errno;

	return 0;
}

/*
 * pset binding hooks for fio
 */
#define fio_setaffinity(pid, cpumask)		\
	pset_bind((cpumask), P_PID, (pid), NULL)
#define fio_getaffinity(pid, ptr)	({ 0; })

#define fio_cpu_clear(mask, cpu)	pset_assign(PS_NONE, (cpu), NULL)
#define fio_cpu_set(mask, cpu)		pset_assign(*(mask), (cpu), NULL)

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

static inline int gettid(void)
{
	return pthread_self();
}

/*
 * Should be enough, not aware of what (if any) restrictions Solaris has
 */
#define FIO_MAX_CPUS			16384

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
