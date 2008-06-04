#ifndef FIO_OS_SOLARIS_H
#define FIO_OS_SOLARIS_H

#include <sys/types.h>
#include <sys/fcntl.h>

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_SOLARISAIO
#define FIO_HAVE_FALLOCATE
#define FIO_HAVE_POSIXAIO_FSYNC

#define OS_MAP_ANON		(MAP_ANON)

struct solaris_rand_seed {
	unsigned short r[3];
};

typedef unsigned long os_cpu_mask_t;
typedef struct solaris_rand_seed os_random_state_t;

/*
 * FIXME
 */
static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	return EINVAL;
}

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

#endif
