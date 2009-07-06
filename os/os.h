#ifndef FIO_OS_H
#define FIO_OS_H

#if defined(__linux__)
#include "os-linux.h"
#elif defined(__FreeBSD__)
#include "os-freebsd.h"
#elif defined(__sun__)
#include "os-solaris.h"
#else
#error "unsupported os"
#endif

#ifdef FIO_HAVE_LIBAIO
#include <libaio.h>
#endif

#ifdef FIO_HAVE_POSIXAIO
#include <aio.h>
#endif

#ifdef FIO_HAVE_SGIO
#include <linux/fs.h>
#include <scsi/sg.h>
#endif

#ifndef FIO_HAVE_STRSEP
#include "../lib/strsep.h"
#endif

#ifndef FIO_HAVE_FADVISE
#define fadvise(fd, off, len, advice)	(0)

#ifndef POSIX_FADV_DONTNEED
#define POSIX_FADV_DONTNEED	(0)
#define POSIX_FADV_SEQUENTIAL	(0)
#define POSIX_FADV_RANDOM	(0)
#endif
#endif /* FIO_HAVE_FADVISE */

#ifndef FIO_HAVE_CPU_AFFINITY
#define fio_setaffinity(pid, mask)	(0)
#define fio_getaffinity(pid, mask)	do { } while (0)
#define fio_cpu_clear(mask, cpu)	do { } while (0)
#define fio_cpuset_exit(mask)		(-1)
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
#ifndef FIO_HUGE_PAGE
#define FIO_HUGE_PAGE			0
#endif
#else
#ifndef FIO_HUGE_PAGE
#define FIO_HUGE_PAGE			4194304
#endif
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

#endif
