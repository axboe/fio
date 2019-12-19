#ifndef FIO_OS_H
#define FIO_OS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

#include "../arch/arch.h" /* IWYU pragma: export */
#include "../lib/types.h"

enum {
	os_linux = 1,
	os_aix,
	os_freebsd,
	os_hpux,
	os_mac,
	os_netbsd,
	os_openbsd,
	os_solaris,
	os_windows,
	os_android,
	os_dragonfly,

	os_nr,
};

typedef enum {
        CPU_ARM64_CRC32C,
} cpu_features;

/* IWYU pragma: begin_exports */
#if defined(__ANDROID__)
#include "os-android.h"
#elif defined(__linux__)
#include "os-linux.h"
#elif defined(__FreeBSD__)
#include "os-freebsd.h"
#elif defined(__OpenBSD__)
#include "os-openbsd.h"
#elif defined(__NetBSD__)
#include "os-netbsd.h"
#elif defined(__sun__)
#include "os-solaris.h"
#elif defined(__APPLE__)
#include "os-mac.h"
#elif defined(_AIX)
#include "os-aix.h"
#elif defined(__hpux)
#include "os-hpux.h"
#elif defined(WIN32)
#include "os-windows.h"
#elif defined (__DragonFly__)
#include "os-dragonfly.h"
#else
#error "unsupported os"
#endif

#ifdef CONFIG_POSIXAIO
#include <aio.h>
#ifndef FIO_OS_HAVE_AIOCB_TYPEDEF
typedef struct aiocb os_aiocb_t;
#endif
#endif

#ifndef CONFIG_STRSEP
#include "../oslib/strsep.h"
#endif

#ifndef CONFIG_STRLCAT
#include "../oslib/strlcat.h"
#endif
/* IWYU pragma: end_exports */

#ifdef MSG_DONTWAIT
#define OS_MSG_DONTWAIT	MSG_DONTWAIT
#endif

#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED	(0)
#define POSIX_FADV_SEQUENTIAL	(0)
#define POSIX_FADV_RANDOM	(0)
#define POSIX_FADV_NORMAL	(0)
#endif

#ifndef FIO_HAVE_CPU_AFFINITY
#define fio_cpu_clear(mask, cpu)	do { } while (0)
typedef unsigned long os_cpu_mask_t;

static inline int fio_setaffinity(int pid, os_cpu_mask_t cpumask)
{
	return 0;
}

static inline int fio_getaffinity(int pid, os_cpu_mask_t *cpumask)
{
	return -1;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return -1;
}

static inline int fio_cpus_split(os_cpu_mask_t *mask, unsigned int cpu_index)
{
	return 0;
}
#else
extern int fio_cpus_split(os_cpu_mask_t *mask, unsigned int cpu);
#endif

#ifndef FIO_HAVE_IOPRIO
#define ioprio_set(which, who, prioclass, prio)	(0)
#endif

#ifndef FIO_HAVE_ODIRECT
#define OS_O_DIRECT			0
#else
#define OS_O_DIRECT			O_DIRECT
#endif

#ifdef OS_O_ATOMIC
#define FIO_O_ATOMIC			OS_O_ATOMIC
#else
#define FIO_O_ATOMIC			0
#endif

#ifndef FIO_HAVE_HUGETLB
#define SHM_HUGETLB			0
#define MAP_HUGETLB			0
#ifndef FIO_HUGE_PAGE
#define FIO_HUGE_PAGE			0
#endif
#else
#ifndef FIO_HUGE_PAGE
#define FIO_HUGE_PAGE			4194304
#endif
#endif

#ifndef FIO_HAVE_MMAP_HUGE
#define MAP_HUGETLB			0
#endif

#ifndef FIO_O_NOATIME
#define FIO_O_NOATIME			0
#endif

#ifndef OS_RAND_MAX
#define OS_RAND_MAX			RAND_MAX
#endif

#ifndef FIO_HAVE_RAWBIND
#define fio_lookup_raw(dev, majdev, mindev)	1
#endif

#ifndef FIO_PREFERRED_ENGINE
#define FIO_PREFERRED_ENGINE	"psync"
#endif

#ifndef FIO_OS_PATH_SEPARATOR
#define FIO_OS_PATH_SEPARATOR	'/'
#endif

#ifndef FIO_PREFERRED_CLOCK_SOURCE
#ifdef CONFIG_CLOCK_GETTIME
#define FIO_PREFERRED_CLOCK_SOURCE	CS_CGETTIME
#else
#define FIO_PREFERRED_CLOCK_SOURCE	CS_GTOD
#endif
#endif

#ifndef FIO_MAX_JOBS
#define FIO_MAX_JOBS		4096
#endif

#ifndef CONFIG_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

#ifndef FIO_OS_HAS_CTIME_R
#define os_ctime_r(x, y, z)     (void) ctime_r((x), (y))
#endif

#ifdef FIO_USE_GENERIC_SWAP
static inline uint16_t fio_swap16(uint16_t val)
{
	return (val << 8) | (val >> 8);
}

static inline uint32_t fio_swap32(uint32_t val)
{
	val = ((val & 0xff00ff00UL) >> 8) | ((val & 0x00ff00ffUL) << 8);

	return (val >> 16) | (val << 16);
}

static inline uint64_t fio_swap64(uint64_t val)
{
	val = ((val & 0xff00ff00ff00ff00ULL) >> 8) |
	      ((val & 0x00ff00ff00ff00ffULL) << 8);
	val = ((val & 0xffff0000ffff0000ULL) >> 16) |
	      ((val & 0x0000ffff0000ffffULL) << 16);

	return (val >> 32) | (val << 32);
}
#endif

#ifndef FIO_HAVE_BYTEORDER_FUNCS
#ifdef CONFIG_LITTLE_ENDIAN
#define __be16_to_cpu(x)		fio_swap16(x)
#define __be32_to_cpu(x)		fio_swap32(x)
#define __be64_to_cpu(x)		fio_swap64(x)
#define __le16_to_cpu(x)		(x)
#define __le32_to_cpu(x)		(x)
#define __le64_to_cpu(x)		(x)
#define __cpu_to_be16(x)		fio_swap16(x)
#define __cpu_to_be32(x)		fio_swap32(x)
#define __cpu_to_be64(x)		fio_swap64(x)
#define __cpu_to_le16(x)		(x)
#define __cpu_to_le32(x)		(x)
#define __cpu_to_le64(x)		(x)
#else
#define __be16_to_cpu(x)		(x)
#define __be32_to_cpu(x)		(x)
#define __be64_to_cpu(x)		(x)
#define __le16_to_cpu(x)		fio_swap16(x)
#define __le32_to_cpu(x)		fio_swap32(x)
#define __le64_to_cpu(x)		fio_swap64(x)
#define __cpu_to_be16(x)		(x)
#define __cpu_to_be32(x)		(x)
#define __cpu_to_be64(x)		(x)
#define __cpu_to_le16(x)		fio_swap16(x)
#define __cpu_to_le32(x)		fio_swap32(x)
#define __cpu_to_le64(x)		fio_swap64(x)
#endif
#endif /* FIO_HAVE_BYTEORDER_FUNCS */

#ifdef FIO_INTERNAL
#define be16_to_cpu(val) ({			\
	typecheck(uint16_t, val);		\
	__be16_to_cpu(val);			\
})
#define be32_to_cpu(val) ({			\
	typecheck(uint32_t, val);		\
	__be32_to_cpu(val);			\
})
#define be64_to_cpu(val) ({			\
	typecheck(uint64_t, val);		\
	__be64_to_cpu(val);			\
})
#define le16_to_cpu(val) ({			\
	typecheck(uint16_t, val);		\
	__le16_to_cpu(val);			\
})
#define le32_to_cpu(val) ({			\
	typecheck(uint32_t, val);		\
	__le32_to_cpu(val);			\
})
#define le64_to_cpu(val) ({			\
	typecheck(uint64_t, val);		\
	__le64_to_cpu(val);			\
})
#endif

#define cpu_to_be16(val) ({			\
	typecheck(uint16_t, val);		\
	__cpu_to_be16(val);			\
})
#define cpu_to_be32(val) ({			\
	typecheck(uint32_t, val);		\
	__cpu_to_be32(val);			\
})
#define cpu_to_be64(val) ({			\
	typecheck(uint64_t, val);		\
	__cpu_to_be64(val);			\
})
#define cpu_to_le16(val) ({			\
	typecheck(uint16_t, val);		\
	__cpu_to_le16(val);			\
})
#define cpu_to_le32(val) ({			\
	typecheck(uint32_t, val);		\
	__cpu_to_le32(val);			\
})
#define cpu_to_le64(val) ({			\
	typecheck(uint64_t, val);		\
	__cpu_to_le64(val);			\
})

#define FIO_DEF_CL_SIZE		128

static inline int os_cache_line_size(void)
{
#ifdef FIO_HAVE_CL_SIZE
	int ret = arch_cache_line_size();

	if (ret <= 0)
		return FIO_DEF_CL_SIZE;

	return ret;
#else
	return FIO_DEF_CL_SIZE;
#endif
}

#ifdef FIO_USE_GENERIC_BDEV_SIZE
static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	off_t end;

	*bytes = 0;

	end = lseek(f->fd, 0, SEEK_END);
	if (end < 0)
		return errno;

	*bytes = end;
	return 0;
}
#endif

#ifdef FIO_USE_GENERIC_INIT_RANDOM_STATE
static inline int init_random_seeds(uint64_t *rand_seeds, int size)
{
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1) {
		return 1;
	}

	if (read(fd, rand_seeds, size) < size) {
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
#endif

#ifndef FIO_HAVE_FS_STAT
static inline unsigned long long get_fs_free_size(const char *path)
{
	return 0;
}
#endif

#ifndef FIO_HAVE_CPU_ONLINE_SYSCONF
static inline unsigned int cpus_online(void)
{
	return sysconf(_SC_NPROCESSORS_ONLN);
}
#endif

#ifndef CPU_COUNT
#ifdef FIO_HAVE_CPU_AFFINITY
static inline int CPU_COUNT(os_cpu_mask_t *mask)
{
	int max_cpus = cpus_online();
	int nr_cpus, i;

	for (i = 0, nr_cpus = 0; i < max_cpus; i++)
		if (fio_cpu_isset(mask, i))
			nr_cpus++;

	return nr_cpus;
}
#endif
#endif

#ifndef FIO_HAVE_GETTID
#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return getpid();
}
#endif
#endif

#ifndef FIO_HAVE_SHM_ATTACH_REMOVED
static inline int shm_attach_to_open_removed(void)
{
	return 0;
}
#endif

#ifndef FIO_HAVE_NATIVE_FALLOCATE
static inline bool fio_fallocate(struct fio_file *f, uint64_t offset, uint64_t len)
{
	errno = ENOSYS;
	return false;
}
#endif

#if defined(CONFIG_POSIX_FALLOCATE) || defined(FIO_HAVE_NATIVE_FALLOCATE)
# define FIO_HAVE_DEFAULT_FALLOCATE
#endif

#ifndef FIO_HAVE_CPU_HAS
static inline bool os_cpu_has(cpu_features feature)
{
	return false;
}
#endif

#ifndef FIO_EMULATED_MKDIR_TWO
# define fio_mkdir(path, mode)	mkdir(path, mode)
#endif

#endif /* FIO_OS_H */
