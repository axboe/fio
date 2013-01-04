#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timeval genesis;
static unsigned long ns_granularity;

/*
 * busy looping version for the last few usec
 */
void usec_spin(unsigned int usec)
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
			usec_spin(usec);
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

uint64_t mtime_since_genesis(void)
{
	return mtime_since_now(&genesis);
}

int in_ramp_time(struct thread_data *td)
{
	return td->o.ramp_time && !td->ramp_time_over;
}

int ramp_time_over(struct thread_data *td)
{
	struct timeval tv;

	if (!td->o.ramp_time || td->ramp_time_over)
		return 1;

	fio_gettime(&tv, NULL);
	if (mtime_since(&td->epoch, &tv) >= td->o.ramp_time * 1000) {
		td->ramp_time_over = 1;
		reset_all_stats(td);
		td_set_runstate(td, TD_RAMP);
		return 1;
	}

	return 0;
}

void fio_time_init(void)
{
	int i;

	fio_clock_init();

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
