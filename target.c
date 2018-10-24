#include <unistd.h>

#include "fio.h"
#include "target.h"
#include "smalloc.h"
#include "stat.h"

void lat_fatal(struct thread_data *td, unsigned long long tnsec,
	       unsigned long long max_nsec)
{
	if (!td->error)
		log_err("fio: latency of %llu nsec exceeds specified max (%llu nsec)\n", tnsec, max_nsec);
	td_verror(td, ETIMEDOUT, "max latency exceeded");
}

static void lat_ios_note(struct thread_data *td)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		td->latency_ios[i] = td->io_blocks[i];
}

static void lat_new_cycle(struct thread_data *td)
{
	fio_gettime(&td->latency_ts, NULL);
	lat_ios_note(td);
	td->latency_failed = 0;
}

/*
 * We had an IO outside the latency target. Reduce the queue depth. If we
 * are at QD=1, then it's time to give up.
 */
static bool __lat_target_failed(struct thread_data *td)
{
	if (td->latency_qd == 1)
		return true;

	td->latency_qd_high = td->latency_qd;

	if (td->latency_qd == td->latency_qd_low)
		td->latency_qd_low--;

	td->latency_qd = (td->latency_qd + td->latency_qd_low) / 2;

	dprint(FD_RATE, "Ramped down: %d %d %d\n", td->latency_qd_low, td->latency_qd, td->latency_qd_high);

	/*
	 * When we ramp QD down, quiesce existing IO to prevent
	 * a storm of ramp downs due to pending higher depth.
	 */
	io_u_quiesce(td);
	lat_new_cycle(td);
	return false;
}

bool lat_target_failed(struct thread_data *td)
{
	if (td->o.latency_percentile.u.f == 100.0)
		return __lat_target_failed(td);

	td->latency_failed++;
	return false;
}

static void lat_step_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	fio_gettime(&td->latency_ts, NULL);
	td->latency_state = IOD_STATE_PROBE_RAMP;
	td->latency_step = 0;
	td->latency_qd = td->o.iodepth;
	dprint(FD_RATE, "Stepped: %d-%d/%d,%d/%d\n", o->lat_step_low,
				o->lat_step_high, o->lat_step_inc,
				o->lat_step_ramp, o->lat_step_run);
}

void lat_target_init(struct thread_data *td)
{
	td->latency_end_run = 0;

	if (td->o.latency_target) {
		dprint(FD_RATE, "Latency target=%llu\n", td->o.latency_target);
		fio_gettime(&td->latency_ts, NULL);
		td->latency_qd = 1;
		td->latency_qd_high = td->o.iodepth;
		td->latency_qd_low = 1;
		lat_ios_note(td);
	} else if (td->o.iodepth_mode == IOD_STEPPED)
		lat_step_init(td);
	else
		td->latency_qd = td->o.iodepth;
}

void lat_target_reset(struct thread_data *td)
{
	if (td->o.latency_target && !td->latency_end_run)
		lat_target_init(td);
}

static void lat_target_success(struct thread_data *td)
{
	const unsigned int qd = td->latency_qd;
	struct thread_options *o = &td->o;

	td->latency_qd_low = td->latency_qd;

	/*
	 * If we haven't failed yet, we double up to a failing value instead
	 * of bisecting from highest possible queue depth. If we have set
	 * a limit other than td->o.iodepth, bisect between that.
	 */
	if (td->latency_qd_high != o->iodepth)
		td->latency_qd = (td->latency_qd + td->latency_qd_high) / 2;
	else
		td->latency_qd *= 2;

	if (td->latency_qd > o->iodepth)
		td->latency_qd = o->iodepth;

	dprint(FD_RATE, "Ramped up: %d %d %d\n", td->latency_qd_low, td->latency_qd, td->latency_qd_high);

	/*
	 * Same as last one, we are done. Let it run a latency cycle, so
	 * we get only the results from the targeted depth.
	 */
	if (td->latency_qd == qd) {
		if (td->latency_end_run) {
			dprint(FD_RATE, "We are done\n");
			td->done = 1;
		} else {
			dprint(FD_RATE, "Quiesce and final run\n");
			io_u_quiesce(td);
			td->latency_end_run = 1;
			reset_all_stats(td);
			reset_io_stats(td);
		}
	}

	lat_new_cycle(td);
}

void __lat_target_check(struct thread_data *td)
{
	uint64_t usec_window;
	uint64_t ios;
	double success_ios;

	usec_window = utime_since_now(&td->latency_ts);
	if (usec_window < td->o.latency_window)
		return;

	ios = ddir_rw_sum(td->io_blocks) - ddir_rw_sum(td->latency_ios);
	success_ios = (double) (ios - td->latency_failed) / (double) ios;
	success_ios *= 100.0;

	dprint(FD_RATE, "Success rate: %.2f%% (target %.2f%%)\n", success_ios, td->o.latency_percentile.u.f);

	if (success_ios >= td->o.latency_percentile.u.f)
		lat_target_success(td);
	else
		__lat_target_failed(td);
}

static void lat_clear_rate(struct thread_data *td)
{
	int i;

	td->flags &= ~TD_F_CHECK_RATE;
	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		td->o.rate_iops[i] = 0;
}

/*
 * Returns true if we're done stepping
 */
static bool lat_step_recalc(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	unsigned int cur, perc;

	cur = td->latency_step * o->lat_step_inc;
	if (cur >= o->lat_step_high)
		return true;

	perc = (td->latency_step + 1) * o->lat_step_inc;
	if (perc < 100) {
		int i;

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			unsigned int this_iops;

			this_iops = (perc * td->latency_iops[i]) / 100;
			td->o.rate_iops[i] = this_iops;
		}
		setup_rate(td);
		td->flags |= TD_F_CHECK_RATE;
		td->latency_qd = td->o.iodepth * 100 / o->lat_step_high;
	} else {
		td->latency_qd = td->o.iodepth * perc / o->lat_step_high;
		lat_clear_rate(td);
	}
		
	dprint(FD_RATE, "Stepped: step=%d, perc=%d, qd=%d\n", td->latency_step,
						perc, td->latency_qd);
	return false;
}

static void lat_step_reset(struct thread_data *td)
{
	struct thread_stat *ts = &td->ts;
	struct io_stat *ios = &ts->clat_stat[DDIR_RWDIR_CNT];

	ios->max_val = ios->min_val = ios->samples = 0;
	ios->mean.u.f = ios->S.u.f = 0;

	lat_clear_rate(td);
	reset_all_stats(td);
	reset_io_stats(td);
}

static uint64_t lat_iops_since(struct thread_data *td, uint64_t msec,
			       enum fio_ddir ddir)
{
	if (msec) {
		uint64_t ios;

		ios = td->io_blocks[ddir] - td->latency_ios[ddir];
		return (ios * 1000) / msec;
	}

	return 0;
}

static void lat_step_add_sample(struct thread_data *td, uint64_t msec)
{
	struct thread_stat *ts = &td->ts;
	unsigned long long min, max;
	struct lat_step_stats *ls;
	double mean[DDIR_RWDIR_CNT], dev;
	int i;

	if (td->nr_lat_stats == ARRAY_SIZE(td->ts.step_stats)) {
		log_err("fio: ts->step_stats too small, dropping entries\n");
		return;
	}

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		calc_lat(&ts->clat_stat[i], &min, &max, &mean[i], &dev);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		ls = &td->ts.step_stats[td->nr_lat_stats];

		ls->iops[i] = lat_iops_since(td, msec, i);
		ls->avg[i].u.f = mean[i];
	}

	td->nr_lat_stats++;
}

bool __lat_ts_has_stats(struct thread_stat *ts, enum fio_ddir ddir)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ts->step_stats); i++) {
		struct lat_step_stats *ls = &ts->step_stats[i];

		if (ls->iops[ddir])
			return true;
	}

	return false;
}

bool lat_ts_has_stats(struct thread_stat *ts)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		if (__lat_ts_has_stats(ts, i))
			return true;

	return false;
}

void lat_step_report(struct thread_stat *ts, struct buf_output *out)
{
	int i, j;

	for (i = 0; i < ARRAY_SIZE(ts->step_stats); i++) {
		struct lat_step_stats *ls = &ts->step_stats[i];

		for (j = 0; j < DDIR_RWDIR_CNT; j++) {
			if (!ls->iops[j])
				continue;

			__log_buf(out, "    %s: iops=%llu, lat=%.1f nsec\n",
					io_ddir_name(j),
					(unsigned long long) ls->iops[j],
					ls->avg[j].u.f);
		}
	}
}

static void lat_next_state(struct thread_data *td, int new_state)
{
	td->latency_state = new_state;
	fio_gettime(&td->latency_ts, NULL);
}

bool lat_step_check(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	uint64_t msec;

	msec = mtime_since_now(&td->latency_ts);

	switch (td->latency_state) {
	case IOD_STATE_PROBE_RAMP:
		if (msec < o->lat_step_ramp)
			break;

		lat_step_reset(td);
		lat_ios_note(td);

		lat_next_state(td, IOD_STATE_PROBE_RUN);
		break;
	case IOD_STATE_PROBE_RUN: {
		int i;

		if (msec < o->lat_step_run)
			break;

		io_u_quiesce(td);

		for (i = 0; i < DDIR_RWDIR_CNT; i++)
			td->latency_iops[i] = lat_iops_since(td, msec, i);

		lat_step_reset(td);
		lat_step_recalc(td);

		io_u_quiesce(td);
		lat_next_state(td, IOD_STATE_RAMP);
		break;
		}
	case IOD_STATE_RAMP:
		if (msec < o->lat_step_ramp)
			break;

		lat_ios_note(td);
		lat_next_state(td, IOD_STATE_RUN);
		break;
	case IOD_STATE_RUN:
		if (msec < o->lat_step_run)
			break;

		io_u_quiesce(td);
		fio_gettime(&td->latency_ts, NULL);
		td->latency_step++;

		lat_step_add_sample(td, msec);
		lat_step_reset(td);

		if (!lat_step_recalc(td))
			break;

		td->done = 1;
		lat_next_state(td, IOD_STATE_DONE);
		break;
	};

	return td->latency_state == IOD_STATE_DONE;
}
