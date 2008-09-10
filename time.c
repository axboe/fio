#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timeval genesis;
static unsigned long ns_granularity;

unsigned long long utime_since(struct timeval *s, struct timeval *e)
{
	long sec, usec;
	unsigned long long ret;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	/*
	 * time warp bug on some kernels?
	 */
	if (sec < 0 || (sec == 0 && usec < 0))
		return 0;

	ret = sec * 1000000ULL + usec;

	return ret;
}

unsigned long long utime_since_now(struct timeval *s)
{
	struct timeval t;

	fio_gettime(&t, NULL);
	return utime_since(s, &t);
}

unsigned long mtime_since(struct timeval *s, struct timeval *e)
{
	long sec, usec, ret;

	sec = e->tv_sec - s->tv_sec;
	usec = e->tv_usec - s->tv_usec;
	if (sec > 0 && usec < 0) {
		sec--;
		usec += 1000000;
	}

	sec *= 1000UL;
	usec /= 1000UL;
	ret = sec + usec;

	/*
	 * time warp bug on some kernels?
	 */
	if (ret < 0)
		ret = 0;

	return ret;
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
	struct timespec req;
	struct timeval tv;

	do {
		unsigned long ts = usec;

		if (usec < ns_granularity) {
			__usec_sleep(usec);
			break;
		}

		ts = usec - ns_granularity;

		if (ts >= 1000000) {
			req.tv_sec = ts / 1000000;
			ts -= 1000000 * req.tv_sec;
		} else
			req.tv_sec = 0;

		req.tv_nsec = ts * 1000;
		fio_gettime(&tv, NULL);

		if (nanosleep(&req, NULL) < 0)
			break;

		ts = utime_since_now(&tv);
		if (ts >= usec)
			break;

		usec -= ts;
	} while (!td->terminate);
}

void rate_throttle(struct thread_data *td, unsigned long time_spent,
		   unsigned int bytes)
{
	unsigned long usec_cycle;
	unsigned int bs;

	if (!td->o.rate && !td->o.rate_iops)
		return;

	if (td_rw(td))
		bs = td->o.rw_min_bs;
	else if (td_read(td))
		bs = td->o.min_bs[DDIR_READ];
	else
		bs = td->o.min_bs[DDIR_WRITE];

	usec_cycle = td->rate_usec_cycle * (bytes / bs);

	if (time_spent < usec_cycle) {
		unsigned long s = usec_cycle - time_spent;

		td->rate_pending_usleep += s;

		if (td->rate_pending_usleep >= 100000) {
			struct timeval t;

			fio_gettime(&t, NULL);
			usec_sleep(td, td->rate_pending_usleep);
			td->rate_pending_usleep -= utime_since_now(&t);
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

int ramp_time_over(struct thread_data *td)
{
	struct timeval tv;

	if (!td->o.ramp_time || td->ramp_time_over)
		return 1;

	fio_gettime(&tv, NULL);
	if (mtime_since(&td->epoch, &tv) >= td->o.ramp_time * 1000) {
		td->ramp_time_over = 1;
		memcpy(&td->start, &tv, sizeof(tv));
		return 1;
	}

	return 0;
}

static void fio_init time_init(void)
{
	int i;

	/*
	 * Check the granularity of the nanosleep function
	 */
	for (i = 0; i < 10; i++) {
		struct timeval tv;
		struct timespec ts;
		unsigned long elapsed;

		fio_gettime(&tv, NULL);
		ts.tv_sec = 0;
		ts.tv_nsec = 1000;

		nanosleep(&ts, NULL);
		elapsed = utime_since_now(&tv);

		if (elapsed > ns_granularity)
			ns_granularity = elapsed;
	}
}

void set_genesis_time(void)
{
	fio_gettime(&genesis, NULL);
}

void fill_start_time(struct timeval *t)
{
	memcpy(t, &genesis, sizeof(genesis));
}
