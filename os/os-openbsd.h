#ifndef FIO_OS_OPENBSD_H
#define FIO_OS_OPENBSD_H

#define	FIO_OS	os_openbsd

#include <errno.h>
#include <sys/param.h>
#include <sys/statvfs.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>
#include <sys/disklabel.h>
#include <sys/endian.h>
#include <sys/utsname.h>
#include <sys/sysctl.h>

/* XXX hack to avoid conflicts between rbtree.h and <sys/tree.h> */
#undef RB_BLACK
#undef RB_RED
#undef RB_ROOT

#include "../file.h"

#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_GETTID
#define FIO_HAVE_SHM_ATTACH_REMOVED

#define OS_MAP_ANON		MAP_ANON

#ifndef PTHREAD_STACK_MIN
#define PTHREAD_STACK_MIN 4096
#endif

#define fio_swap16(x)	swap16(x)
#define fio_swap32(x)	swap32(x)
#define fio_swap64(x)	swap64(x)

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

#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return (int)(intptr_t) pthread_self();
}
#endif

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

static inline int shm_attach_to_open_removed(void)
{
	struct utsname uts;
	int major, minor;

	if (uname(&uts) == -1)
		return 0;

	/*
	 * Return 1 if >= OpenBSD 5.1 according to 97900ebf,
	 * assuming both major/minor versions are < 10.
	 */
	if (uts.release[0] > '9' || uts.release[0] < '0')
		return 0;
	if (uts.release[1] != '.')
		return 0;
	if (uts.release[2] > '9' || uts.release[2] < '0')
		return 0;

	major = uts.release[0] - '0';
	minor = uts.release[2] - '0';

	if (major > 5)
		return 1;
	if (major == 5 && minor >= 1)
		return 1;

	return 0;
}

#endif
