#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timeval genesis;

unsigned long utime_since(struct timeval *s, struct timeval *e)
{
	long sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= (double) 1000000;

	return sec + usec;
}

unsigned long utime_since_now(struct timeval *s)
{
	struct timeval t;

	fio_gettime(&t, NULL);
	return utime_since(s, &t);
}

unsigned long mtime_since(struct timeval *s, struct timeval *e)
{
	long sec, usec;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= (double) 1000;
	usec /= (double) 1000;

	return sec + usec;
}

unsigned long mtime_since_now(struct timeval *s)
{
	struct timeval t;
	void *p = __builtin_return_address(0);

	fio_gettime(&t, p);
	return mtime_since(s, &t);
}

unsigned long time_since_now(struct timeval *s)
{
	return mtime_since_now(s) / 1000;
}

/*
 * busy looping version for the last few usec
 */
void __usec_sleep(unsigned int usec)
{
	struct timeval start;

	fio_gettime(&start, NULL);
	while (utime_since_now(&start) < usec)
		nop;
}

void usec_sleep(struct thread_data *td, unsigned long usec)
{
	struct timespec req, rem;

	req.tv_sec = usec / 1000000;
	req.tv_nsec = usec * 1000 - req.tv_sec * 1000000;

	do {
		if (usec < 5000) {
			__usec_sleep(usec);
			break;
		}

		rem.tv_sec = rem.tv_nsec = 0;
		if (nanosleep(&req, &rem) < 0)
			break;

		if ((rem.tv_sec + rem.tv_nsec) == 0)
			break;

		req.tv_nsec = rem.tv_nsec;
		req.tv_sec = rem.tv_sec;

		usec = rem.tv_sec * 1000000 + rem.tv_nsec / 1000;
	} while (!td->terminate);
}

void rate_throttle(struct thread_data *td, unsigned long time_spent,
		   unsigned int bytes, int ddir)
{
	unsigned long usec_cycle;

	if (!td->rate)
		return;

	usec_cycle = td->rate_usec_cycle * (bytes / td->min_bs[ddir]);

	if (time_spent < usec_cycle) {
		unsigned long s = usec_cycle - time_spent;

		td->rate_pending_usleep += s;
		if (td->rate_pending_usleep >= 100000) {
			usec_sleep(td, td->rate_pending_usleep);
			td->rate_pending_usleep = 0;
		}
	} else {
		long overtime = time_spent - usec_cycle;

		td->rate_pending_usleep -= overtime;
	}
}

unsigned long mtime_since_genesis(void)
{
	return mtime_since_now(&genesis);
}

static void fio_init time_init(void)
{
	fio_gettime(&genesis, NULL);
}

void fill_start_time(struct timeval *t)
{
	memcpy(t, &genesis, sizeof(genesis));
}
