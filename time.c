#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timespec genesis;
static unsigned long ns_granularity;

void timespec_add_msec(struct timespec *ts, unsigned int msec)
{
	uint64_t adj_nsec = 1000000ULL * msec;

	ts->tv_nsec += adj_nsec;
	if (adj_nsec >= 1000000000) {
		uint64_t adj_sec = adj_nsec / 1000000000;

		ts->tv_nsec -= adj_sec * 1000000000;
		ts->tv_sec += adj_sec;
	}
	if (ts->tv_nsec >= 1000000000){
		ts->tv_nsec -= 1000000000;
		ts->tv_sec++;
	}
}

/*
 * busy looping version for the last few usec
 */
uint64_t usec_spin(unsigned int usec)
{
	struct timespec start;
	uint64_t t;

	fio_gettime(&start, NULL);
	while ((t = utime_since_now(&start)) < usec)
		nop;

	return t;
}

uint64_t usec_sleep(struct thread_data *td, unsigned long usec)
{
	struct timespec req;
	struct timespec tv;
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
			/*
			 * Limit sleep to ~1 second at most, otherwise we
			 * don't notice then someone signaled the job to
			 * exit manually.
			 */
			if (req.tv_sec > 1)
				req.tv_sec = 1;
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

static bool parent_update_ramp(struct thread_data *td)
{
	struct thread_data *parent = td->parent;

	if (!parent || parent->ramp_time_over)
		return false;

	reset_all_stats(parent);
	parent->ramp_time_over = true;
	td_set_runstate(parent, TD_RAMP);
	return true;
}

bool ramp_time_over(struct thread_data *td)
{
	if (!td->o.ramp_time || td->ramp_time_over)
		return true;

	if (utime_since_now(&td->epoch) >= td->o.ramp_time) {
		td->ramp_time_over = true;
		reset_all_stats(td);
		reset_io_stats(td);
		td_set_runstate(td, TD_RAMP);

		/*
		 * If we have a parent, the parent isn't doing IO. Hence
		 * the parent never enters do_io(), which will switch us
		 * from RAMP -> RUNNING. Do this manually here.
		 */
		if (parent_update_ramp(td))
			td_set_runstate(td, TD_RUNNING);

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
		struct timespec tv, ts;
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

void fill_start_time(struct timespec *t)
{
	memcpy(t, &genesis, sizeof(genesis));
}
