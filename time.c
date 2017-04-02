#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timeval genesis;
static unsigned long ns_granularity;

void timeval_add_msec(struct timeval *tv, unsigned int msec)
{
	unsigned long adj_usec = 1000 * msec;

	tv->tv_usec += adj_usec;
	if (adj_usec >= 1000000) {
		unsigned long adj_sec = adj_usec / 1000000;

		tv->tv_usec -=  adj_sec * 1000000;
		tv->tv_sec += adj_sec;
	}
	if (tv->tv_usec >= 1000000){
		tv->tv_usec -= 1000000;
		tv->tv_sec++;
	}
}

/*
 * busy looping version for the last few usec
 */
uint64_t usec_spin(unsigned int usec)
{
	struct timeval start;
	uint64_t t;

	fio_gettime(&start, NULL);
	while ((t = utime_since_now(&start)) < usec)
		nop;

	return t;
}

uint64_t usec_sleep(struct thread_data *td, unsigned long usec)
{
	struct timespec req;
	struct timeval tv;
	uint64_t t = 0;

	do {
		unsigned long ts = usec;

		if (usec < ns_granularity) {
			t += usec_spin(usec);
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
		t += ts;
		if (ts >= usec)
			break;

		usec -= ts;
	} while (!td->terminate);

	return t;
}

uint64_t time_since_genesis(void)
{
	return time_since_now(&genesis);
}

uint64_t mtime_since_genesis(void)
{
	return mtime_since_now(&genesis);
}

uint64_t utime_since_genesis(void)
{
	return utime_since_now(&genesis);
}

bool in_ramp_time(struct thread_data *td)
{
	return td->o.ramp_time && !td->ramp_time_over;
}

static void parent_update_ramp(struct thread_data *td)
{
	struct thread_data *parent = td->parent;

	if (!parent || parent->ramp_time_over)
		return;

	reset_all_stats(parent);
	parent->ramp_time_over = 1;
	td_set_runstate(parent, TD_RAMP);
}

bool ramp_time_over(struct thread_data *td)
{
	struct timeval tv;

	if (!td->o.ramp_time || td->ramp_time_over)
		return true;

	fio_gettime(&tv, NULL);
	if (utime_since(&td->epoch, &tv) >= td->o.ramp_time) {
		td->ramp_time_over = 1;
		reset_all_stats(td);
		td_set_runstate(td, TD_RAMP);
		parent_update_ramp(td);
		return true;
	}

	return false;
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

void set_epoch_time(struct thread_data *td, int log_unix_epoch)
{
	fio_gettime(&td->epoch, NULL);
	if (log_unix_epoch) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		td->unix_epoch = (unsigned long long)(tv.tv_sec) * 1000 +
		                 (unsigned long long)(tv.tv_usec) / 1000;
	}
}

void fill_start_time(struct timeval *t)
{
	memcpy(t, &genesis, sizeof(genesis));
}
