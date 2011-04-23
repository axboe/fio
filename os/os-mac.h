#ifndef FIO_OS_APPLE_H
#define FIO_OS_APPLE_H

#include <errno.h>
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>

#include "../file.h"

#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC 1
#endif

#ifndef CLOCK_REALTIME
#define CLOCK_REALTIME 1
#endif

#define FIO_HAVE_POSIXAIO
#define FIO_HAVE_CLOCK_MONOTONIC
#define FIO_USE_GENERIC_RAND

#define OS_MAP_ANON		MAP_ANON

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

static inline int timer_create(clockid_t clockid, struct sigevent *restrict evp,
				 timer_t *restrict timerid)
{
	int current_timer = num_timers;
	fio_timers[current_timer] = *evp;
	num_timers++;
	
	*timerid = current_timer;
	return 0;
}

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
								const struct itimerspec *value, struct itimerspec *ovalue)
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
    uint64_t temp = 1;
    if (ioctl(f->fd, DKIOCGETBLOCKCOUNT, bytes) == -1)
		return errno;
    if (ioctl(f->fd, DKIOCGETBLOCKSIZE, &temp) == -1)
		return errno;
    (*bytes) *= temp;
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
#endif
