#ifndef FIO_OS_OPENBSD_H
#define FIO_OS_OPENBSD_H

#define	FIO_OS	os_openbsd

#include <errno.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>
#include <sys/disklabel.h>
/* XXX hack to avoid conflicts between rbtree.h and <sys/tree.h> */
#include <sys/sysctl.h>
#undef RB_BLACK
#undef RB_RED
#undef RB_ROOT

#include "../file.h"

#undef  FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_GETTID

#undef	FIO_HAVE_CPU_AFFINITY	/* XXX notyet */

/* Only OpenBSD 5.1 and above have attach-to-open-removed semantics */
#undef  FIO_HAVE_SHM_ATTACH_REMOVED

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	bswap16(x)
#define fio_swap32(x)	bswap32(x)
#define fio_swap64(x)	bswap64(x)

typedef off_t off64_t;

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	struct disklabel dl;

	if (!ioctl(f->fd, DIOCGDINFO, &dl)) {
		*bytes = ((unsigned long long)dl.d_secperunit) * dl.d_secsize;
		return 0;
	}

	*bytes = 0;
	return errno;
}

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
	return (int) pthread_self();
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
