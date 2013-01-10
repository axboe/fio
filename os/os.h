#ifndef FIO_OS_H
#define FIO_OS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>

enum {
	os_linux = 1,
	os_aix,
	os_freebsd,
	os_hpux,
	os_mac,
	os_netbsd,
	os_solaris,
	os_windows,
	os_android,

	os_nr,
};

#if defined(__ANDROID__)
#include "os-android.h"
#elif defined(__linux__)
#include "os-linux.h"
#elif defined(__FreeBSD__)
#include "os-freebsd.h"
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
#else
#error "unsupported os"
#endif

#ifdef CONFIG_POSIXAIO
#include <aio.h>
#ifndef FIO_OS_HAVE_AIOCB_TYPEDEF
typedef struct aiocb os_aiocb_t;
#endif
#endif

#ifdef FIO_HAVE_SGIO
#include <linux/fs.h>
#include <scsi/sg.h>
#endif

#ifdef CONFIG_STRSEP
#include "../lib/strsep.h"
#endif

#ifdef MSG_DONTWAIT
#define OS_MSG_DONTWAIT	MSG_DONTWAIT
#endif

#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED	(0)
#define POSIX_FADV_SEQUENTIAL	(0)
#define POSIX_FADV_RANDOM	(0)
#endif

#ifndef FIO_HAVE_CPU_AFFINITY
#define fio_setaffinity(pid, mask)	(0)
#define fio_getaffinity(pid, mask)	do { } while (0)
#define fio_cpu_clear(mask, cpu)	do { } while (0)
#define fio_cpuset_exit(mask)		(-1)
typedef unsigned long os_cpu_mask_t;
#endif

#ifndef FIO_HAVE_IOPRIO
#define ioprio_set(which, who, prio)	(0)
#endif

#ifndef FIO_HAVE_ODIRECT
#define OS_O_DIRECT			0
#else
#define OS_O_DIRECT			O_DIRECT
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
#define FIO_PREFERRED_ENGINE	"sync"
#endif

#ifndef FIO_OS_PATH_SEPARATOR
#define FIO_OS_PATH_SEPARATOR	"/"
#endif

#ifndef FIO_PREFERRED_CLOCK_SOURCE
#define FIO_PREFERRED_CLOCK_SOURCE	CS_CGETTIME
#endif

#ifndef FIO_MAX_JOBS
#define FIO_MAX_JOBS		2048
#endif

#ifndef CONFIG_SOCKLEN_T
typedef unsigned int socklen_t;
#endif

#ifndef FIO_OS_HAS_CTIME_R
#define os_ctime_r(x, y, z)     ctime_r((x), (y))
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
#ifdef FIO_LITTLE_ENDIAN
#define __le16_to_cpu(x)		(x)
#define __le32_to_cpu(x)		(x)
#define __le64_to_cpu(x)		(x)
#define __cpu_to_le16(x)		(x)
#define __cpu_to_le32(x)		(x)
#define __cpu_to_le64(x)		(x)
#else
#define __le16_to_cpu(x)		fio_swap16(x)
#define __le32_to_cpu(x)		fio_swap32(x)
#define __le64_to_cpu(x)		fio_swap64(x)
#define __cpu_to_le16(x)		fio_swap16(x)
#define __cpu_to_le32(x)		fio_swap32(x)
#define __cpu_to_le64(x)		fio_swap64(x)
#endif
#endif /* FIO_HAVE_BYTEORDER_FUNCS */

#define le16_to_cpu(val) ({			\
	uint16_t *__val = &(val);		\
	__le16_to_cpu(*__val);			\
})
#define le32_to_cpu(val) ({			\
	uint32_t *__val = &(val);		\
	__le32_to_cpu(*__val);			\
})
#define le64_to_cpu(val) ({			\
	uint64_t *__val = &(val);		\
	__le64_to_cpu(*__val);			\
})
#define cpu_to_le16(val) ({			\
	uint16_t *__val = &(val);		\
	__cpu_to_le16(*__val);			\
})
#define cpu_to_le32(val) ({			\
	uint32_t *__val = &(val);		\
	__cpu_to_le32(*__val);			\
})
#define cpu_to_le64(val) ({			\
	uint64_t *__val = &(val);		\
	__cpu_to_le64(*__val);			\
})

#ifndef FIO_HAVE_BLKTRACE
static inline int is_blktrace(const char *fname)
{
	return 0;
}
struct thread_data;
static inline int load_blktrace(struct thread_data *td, const char *fname)
{
	return 1;
}
#endif

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

#ifdef FIO_USE_GENERIC_RAND
typedef unsigned int os_random_state_t;

static inline void os_random_seed(unsigned long seed, os_random_state_t *rs)
{
	srand(seed);
}

static inline long os_random_long(os_random_state_t *rs)
{
	long val;

	val = rand_r(rs);
	return val;
}
#endif

#ifdef FIO_USE_GENERIC_INIT_RANDOM_STATE
extern void td_fill_rand_seeds(struct thread_data *td);
/*
 * Initialize the various random states we need (random io, block size ranges,
 * read/write mix, etc).
 */
static inline int init_random_state(struct thread_data *td, unsigned long *rand_seeds, int size)
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
	td_fill_rand_seeds(td);
	return 0;
}
#endif

#ifndef FIO_HAVE_FS_STAT
static inline unsigned long long get_fs_size(const char *path)
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

#ifndef FIO_HAVE_GETTID
static inline int gettid(void)
{
	return getpid();
}
#endif

#endif
