#include <time.h>
#include <sys/time.h>

#include "fio.h"

static struct timespec genesis;
static unsigned long ns_granularity;

enum ramp_period_states {
	RAMP_RUNNING,
	RAMP_FINISHING,
	RAMP_DONE
};

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

/*
 * busy loop for a fixed amount of cycles
 */
void cycles_spin(unsigned int n)
{
	unsigned long i;

	for (i=0; i < n; i++)
		nop;
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

bool in_ramp_period(struct thread_data *td)
{
	return td->ramp_period_state != RAMP_DONE;
}

bool ramp_period_enabled = false;

int ramp_period_check(void)
{
	uint64_t group_bytes = 0;
	int prev_groupid = -1;
	bool group_ramp_period_over = false;

	for_each_td(td) {
		if (td->ramp_period_state != RAMP_RUNNING)
			continue;

		if (td->o.ramp_time &&
		    utime_since_now(&td->epoch) >= td->o.ramp_time) {
			td->ramp_period_state = RAMP_FINISHING;
			continue;
		}

		if (td->o.ramp_size) {
			int ddir;
			const bool needs_lock = td_async_processing(td);

			if (!td->o.group_reporting ||
			    (td->o.group_reporting &&
			     td->groupid != prev_groupid)) {
				group_bytes = 0;
				prev_groupid = td->groupid;
				group_ramp_period_over = false;
			}

			if (needs_lock)
				__td_io_u_lock(td);

			for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++)
				group_bytes += td->io_bytes[ddir];

			if (needs_lock)
				__td_io_u_unlock(td);

			if (group_bytes >= td->o.ramp_size) {
				td->ramp_period_state = RAMP_FINISHING;
				/*
				 * Mark ramp up for all threads in the group as
				 * done.
				 */
				if (td->o.group_reporting &&
				    !group_ramp_period_over) {
					group_ramp_period_over = true;
					for_each_td(td2) {
						if (td2->groupid == td->groupid)
							 td2->ramp_period_state = RAMP_FINISHING;
					} end_for_each();
				}
			}
		}
	} end_for_each();

	return 0;
}

static bool parent_update_ramp(struct thread_data *td)
{
	struct thread_data *parent = td->parent;

	if (!parent || parent->ramp_period_state == RAMP_DONE)
		return false;

	reset_all_stats(parent);
	parent->ramp_period_state = RAMP_DONE;
	td_set_runstate(parent, TD_RAMP);
	return true;
}


bool ramp_period_over(struct thread_data *td)
{
	if (td->ramp_period_state == RAMP_DONE)
		return true;

	if (td->ramp_period_state == RAMP_RUNNING)
		return false;

	td->ramp_period_state = RAMP_DONE;
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

int td_ramp_period_init(struct thread_data *td)
{
	if (td->o.ramp_time || td->o.ramp_size) {
		if (td->o.ramp_time && td->o.ramp_size) {
			td_verror(td, EINVAL, "job rejected: cannot specify both ramp_time and ramp_size");
			return 1;
		}
		/* Make sure options are consistent within reporting group */
		for_each_td(td2) {
			if (td->groupid == td2->groupid &&
			    td->o.ramp_size != td2->o.ramp_size) {
				td_verror(td, EINVAL, "job rejected: inconsistent ramp_size within reporting group");
				return 1;
			}
		} end_for_each();
		td->ramp_period_state = RAMP_RUNNING;
		ramp_period_enabled = true;
	} else {
		td->ramp_period_state = RAMP_DONE;
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

void set_epoch_time(struct thread_data *td, clockid_t log_alternate_epoch_clock_id, clockid_t job_start_clock_id)
{
	struct timespec ts;
	fio_gettime(&td->epoch, NULL);
	clock_gettime(log_alternate_epoch_clock_id, &ts);
	td->alternate_epoch = (unsigned long long)(ts.tv_sec) * 1000 +
						  (unsigned long long)(ts.tv_nsec) / 1000000;
	if (job_start_clock_id == log_alternate_epoch_clock_id)
	{
		td->job_start = td->alternate_epoch;
	}
	else
	{
		clock_gettime(job_start_clock_id, &ts);
		td->job_start = (unsigned long long)(ts.tv_sec) * 1000 +
						(unsigned long long)(ts.tv_nsec) / 1000000;
	}
}

void fill_start_time(struct timespec *t)
{
	memcpy(t, &genesis, sizeof(genesis));
}
