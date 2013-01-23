#ifndef FIO_OS_APPLE_H
#define FIO_OS_APPLE_H

#define	FIO_OS	os_mac

#include <errno.h>
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <mach/mach_init.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#include "../file.h"

#define FIO_USE_GENERIC_RAND
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID
#define FIO_HAVE_CHARDEV_SIZE

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	OSSwapInt16(x)
#define fio_swap32(x)	OSSwapInt32(x)
#define fio_swap64(x)	OSSwapInt64(x)

/*
 * OSX has a pitifully small shared memory segment by default,
 * so default to a lower number of max jobs supported
 */
#define FIO_MAX_JOBS		128

typedef off_t off64_t;

/* OS X as of 10.6 doesn't have the timer_* functions. 
 * Emulate the functionality using setitimer and sigaction here
 */

#define MAX_TIMERS 64

typedef unsigned int clockid_t;
typedef unsigned int timer_t;

struct itimerspec {
	struct timespec it_value;
	struct timespec it_interval;
};

static struct sigevent fio_timers[MAX_TIMERS];
static unsigned int num_timers = 0;

static void sig_alrm(int signum)
{
	union sigval sv;
	
	for (int i = 0; i < num_timers; i++) {
		if (fio_timers[i].sigev_notify_function == NULL)
			continue;
		
		if (fio_timers[i].sigev_notify == SIGEV_THREAD)
			fio_timers[i].sigev_notify_function(sv);
		else if (fio_timers[i].sigev_notify == SIGEV_SIGNAL)
			kill(getpid(), fio_timers[i].sigev_signo);
	}
}

static inline int timer_settime(timer_t timerid, int flags,
				const struct itimerspec *value,
				struct itimerspec *ovalue)
{
	struct sigaction sa;
	struct itimerval tv;
	struct itimerval tv_out;
	int rc;
	
	tv.it_interval.tv_sec = value->it_interval.tv_sec;
	tv.it_interval.tv_usec = value->it_interval.tv_nsec / 1000;

	tv.it_value.tv_sec = value->it_value.tv_sec;
	tv.it_value.tv_usec = value->it_value.tv_nsec / 1000;

	sa.sa_handler = sig_alrm;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;
	
	rc = sigaction(SIGALRM, &sa, NULL);

	if (!rc)
		rc = setitimer(ITIMER_REAL, &tv, &tv_out);
	
	if (!rc && ovalue != NULL) {
		ovalue->it_interval.tv_sec = tv_out.it_interval.tv_sec;
		ovalue->it_interval.tv_nsec = tv_out.it_interval.tv_usec * 1000;
		ovalue->it_value.tv_sec = tv_out.it_value.tv_sec;
		ovalue->it_value.tv_nsec = tv_out.it_value.tv_usec * 1000;
	}

	return rc;
}

static inline int timer_delete(timer_t timer)
{
	return 0;
}

#define FIO_OS_DIRECTIO
static inline int fio_set_odirect(int fd)
{
	if (fcntl(fd, F_NOCACHE, 1) == -1)
		return errno;
	return 0;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	uint32_t block_size;
	uint64_t block_count;

	if (ioctl(f->fd, DKIOCGETBLOCKCOUNT, &block_count) == -1)
		return errno;
	if (ioctl(f->fd, DKIOCGETBLOCKSIZE, &block_size) == -1)
		return errno;

	*bytes = block_size;
	*bytes *= block_count;
	return 0;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	/*
	 * Could be a raw block device, this is better than just assuming
	 * we can't get the size at all.
	 */
	if (!blockdev_size(f, bytes))
		return 0;

	*bytes = -1ULL;
	return 0;
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return EINVAL;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM };
	unsigned long long mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

static inline int gettid(void)
{
	return mach_thread_self();
}

/*
 * For some reason, there's no header definition for fdatasync(), even
 * if it exists.
 */
extern int fdatasync(int fd);

#endif
