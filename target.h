#ifndef FIO_LAT_TARGET_H
#define FIO_LAT_TARGET_H

#include "fio.h"

enum {
	IOD_STEPPED_DEF_RAMP	= 5000,
	IOD_STEPPED_DEF_RUN	= 30000,
};

/*
 * Starts out as PROBE_RAMP -> PROBE_RUN, then iterations of
 * RAMP -> RUN with various iops limiting settings
 */
enum {
	IOD_STATE_PROBE_RAMP = 1,
	IOD_STATE_PROBE_RUN,
	IOD_STATE_RAMP,
	IOD_STATE_RUN,
	IOD_STATE_DONE,
};

/*
 * Latency target helpers
 */
void lat_target_init(struct thread_data *);
void lat_target_reset(struct thread_data *);
bool lat_target_failed(struct thread_data *td);
void lat_step_report(struct thread_stat *ts, struct buf_output *out);
bool lat_ts_has_stats(struct thread_stat *ts);
bool __lat_ts_has_stats(struct thread_stat *ts, enum fio_ddir);

void lat_fatal(struct thread_data *td, unsigned long long tnsec,
		unsigned long long max_nsec);

bool lat_step_check(struct thread_data *td);
void __lat_target_check(struct thread_data *td);

static inline bool lat_target_check(struct thread_data *td)
{
	if (td->o.latency_target) {
		__lat_target_check(td);
		return false;
	} else if (td->o.iodepth_mode == IOD_STEPPED)
		return lat_step_check(td);

	return false;
}

static inline bool lat_step_account(struct thread_data *td)
{
	if (td->o.iodepth_mode != IOD_STEPPED)
		return true;

	return td->latency_state == IOD_STATE_RUN;
}

#endif
