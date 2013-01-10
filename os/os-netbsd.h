#ifndef FIO_OS_NETBSD_H
#define FIO_OS_NETBSD_H

#define	FIO_OS	os_netbsd

#include <errno.h>
#include <lwp.h>
#include <sys/param.h>
#include <sys/endian.h>
/* XXX hack to avoid confilcts between rbtree.h and <sys/rb.h> */
#define	rb_node	_rb_node
#include <sys/sysctl.h>
#undef rb_node
#undef rb_left
#undef rb_right

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID

#undef	FIO_HAVE_CPU_AFFINITY	/* XXX notyet */

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define FIO_LITTLE_ENDIAN
#else
#define FIO_BIG_ENDIAN
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return EINVAL;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM64 };
	uint64_t mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

static inline int gettid(void)
{
	return (int) _lwp_self();
}

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

/* XXX NetBSD doesn't have getopt_long_only */
#define	getopt_long_only	getopt_long

#endif
