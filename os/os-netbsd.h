#ifndef FIO_OS_NETBSD_H
#define FIO_OS_NETBSD_H

#include <errno.h>
#include <sys/param.h>
/* XXX hack to avoid confilcts between rbtree.h and <sys/rb.h> */
#define	rb_node	_rb_node
#include <sys/sysctl.h>
#undef rb_node
#undef rb_left
#undef rb_right

#include "../file.h"

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_FADVISE
#define FIO_HAVE_ODIRECT
#define FIO_HAVE_STRSEP
#define FIO_HAVE_FDATASYNC
#define FIO_HAVE_CLOCK_MONOTONIC
#define FIO_USE_GENERIC_BDEV_SIZE
#define FIO_USE_GENERIC_RAND

#undef	FIO_HAVE_CPU_AFFINITY	/* XXX notyet */

#define OS_MAP_ANON		MAP_ANON

typedef off_t off64_t;

static inline int blockdev_invalidate_cache(struct fio_file fio_unused *f)
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

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

/* XXX NetBSD doesn't have getopt_long_only */
#define	getopt_long_only	getopt_long

#endif
