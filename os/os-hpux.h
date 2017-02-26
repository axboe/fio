#ifndef FIO_OS_HPUX_H
#define FIO_OS_HPUX_H

#define	FIO_OS	os_hpux

#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/fadvise.h>
#include <sys/mman.h>
#include <sys/mpctl.h>
#include <sys/diskio.h>
#include <sys/param.h>
#include <sys/pstat.h>
#include <time.h>
#include <aio.h>
#include <arm.h>

#include "../file.h"

#define FIO_HAVE_ODIRECT
#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_CHARDEV_SIZE

#define OS_MAP_ANON		MAP_ANONYMOUS
#define OS_MSG_DONTWAIT		0

#define POSIX_MADV_DONTNEED	MADV_DONTNEED
#define POSIX_MADV_SEQUENTIAL	MADV_SEQUENTIAL
#define POSIX_MADV_RANDOM	MADV_RANDOM
#define posix_madvise(ptr, sz, hint)	madvise((ptr), (sz), (hint))

#ifndef MSG_WAITALL
#define MSG_WAITALL	0x40
#endif

#define FIO_USE_GENERIC_SWAP

#define FIO_OS_HAVE_AIOCB_TYPEDEF
typedef struct aiocb64 os_aiocb_t;

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	disk_describe_type_ext_t dext;

	if (!ioctl(f->fd, DIOC_DESCRIBE_EXT, &dext)) {
		unsigned long long lba;

		lba = ((uint64_t) dext.maxsva_high << 32) | dext.maxsva_low;
		*bytes = lba * dext.lgblksz;
		return 0;
	}

	*bytes = 0;
	return errno;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	return blockdev_size(f, bytes);
}

static inline unsigned long long os_phys_mem(void)
{
	unsigned long long ret;
	struct pst_static pst;
	union pstun pu;

	pu.pst_static = &pst;
	if (pstat(PSTAT_STATIC, pu, sizeof(pst), 0, 0) == -1)
		return 0;

	ret = pst.physical_memory;
	ret *= pst.page_size;
	return ret;
}

#define FIO_HAVE_CPU_ONLINE_SYSCONF

static inline unsigned int cpus_online(void)
{
	return mpctl(MPC_GETNUMSPUS, 0, NULL);
}

#endif
