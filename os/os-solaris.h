#ifndef FIO_OS_SOLARIS_H
#define FIO_OS_SOLARIS_H

#include <errno.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/fcntl.h>
#include <sys/pset.h>

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_SOLARISAIO
#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_POSIXAIO_FSYNC
#define FIO_HAVE_CPU_AFFINITY
#define FIO_HAVE_PSHARED_MUTEX
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_HAVE_FDATASYNC

#define OS_MAP_ANON		MAP_ANON
#define OS_RAND_MAX		2147483648UL

struct solaris_rand_seed {
	unsigned short r[3];
};

typedef psetid_t os_cpu_mask_t;
typedef struct solaris_rand_seed os_random_state_t;

static inline int blockdev_invalidate_cache(int fd)
{
	return EINVAL;
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
	int ret;

	if (pset_create(mask) < 0) {
		ret = errno;
		return -1;
	}

	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	int ret;

	if (pset_destroy(*mask) < 0) {
		ret = errno;
		return -1;
	}

	return 0;
}

/*
 * Should be enough, not aware of what (if any) restrictions Solaris has
 */
#define FIO_MAX_CPUS			16384

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
