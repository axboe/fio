#ifndef FIO_OS_QNX_H
#define FIO_OS_QNX_H

#define	FIO_OS	os_qnx
#include <stdint.h>
#include <stdio.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/dcmd_cam.h>

/* XXX hack to avoid conflicts between rbtree.h and <sys/tree.h> */
#undef RB_BLACK
#undef RB_RED
#undef RB_ROOT

#include "../file.h"

/* QNX is not supporting SA_RESTART. Use SA_NOCLDSTOP instead of it */
#ifndef SA_RESTART
#define SA_RESTART SA_NOCLDSTOP
#endif

#define FIO_NO_HAVE_SHM_H

typedef uint64_t __u64;
typedef unsigned int __u32;

#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_GETTID

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	swap16(x)
#define fio_swap32(x)	swap32(x)
#define fio_swap64(x)	swap64(x)

#ifdef CONFIG_PTHREAD_GETAFFINITY
#define FIO_HAVE_GET_THREAD_AFFINITY
#define fio_get_thread_affinity(mask)	\
	pthread_getaffinity_np(pthread_self(), sizeof(mask), &(mask))
#endif

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct stat statbuf;

	if (fstat(f->fd, &statbuf) == -1) {
		*bytes = 0;
		return errno;
	}

	*bytes = (unsigned long long)(statbuf.st_blocksize * statbuf.st_nblocks);
	return 0;
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM64 };
	uint64_t mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
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

#ifdef MADV_FREE
#define FIO_MADV_FREE	MADV_FREE
#endif

#endif
