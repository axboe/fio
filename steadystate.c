#include "fio.h"
#include "steadystate.h"
#include "helper_thread.h"

void steadystate_setup()
{
	int i, prev_groupid;
	struct thread_data *td, *prev_td;

	if (!steadystate)
		return;

	/*
	 * if group reporting is enabled, identify the last td
	 * for each group and use it for storing steady state
	 * data
	 */
	prev_groupid = -1;
	prev_td = NULL;
	for_each_td(td, i) {
		if (!td->o.group_reporting)
			continue;

		if (prev_groupid != td->groupid) {
			if (prev_td != NULL)
				prev_td->ss.last_in_group = 1;
			prev_groupid = td->groupid;
		}
		prev_td = td;
	}

	if (prev_td != NULL && prev_td->o.group_reporting)
		prev_td->ss.last_in_group = 1;
}

void steadystate_check()
{
	int i, j, ddir, prev_groupid, group_ramp_time_over = 0;
	unsigned long rate_time;
	struct thread_data *td, *td2;
	struct timeval now;
	unsigned long group_bw = 0, group_iops = 0;
	unsigned long long td_iops;
	unsigned long long td_bytes;

	prev_groupid = -1;
	for_each_td(td, i) {
		struct steadystate_data *ss = &td->ss;

		if (!ss->dur || td->runstate <= TD_SETTING_UP || td->runstate >= TD_EXITED || ss->attained)
			continue;

		td_iops = 0;
		td_bytes = 0;
		if (!td->o.group_reporting ||
		    (td->o.group_reporting && td->groupid != prev_groupid)) {
			group_bw = 0;
			group_iops = 0;
			group_ramp_time_over = 0;
		}
		prev_groupid = td->groupid;

		fio_gettime(&now, NULL);
		if (ss->ramp_time && !ss->ramp_time_over)
			/* 
			 * Begin recording data one second after ss->ramp_time
			 * has elapsed
			 */
			if (utime_since(&td->epoch, &now) >= (ss->ramp_time + 1000000L))
				ss->ramp_time_over = 1;

		for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
			td_iops += td->io_blocks[ddir];
			td_bytes += td->io_bytes[ddir];
		}

		rate_time = mtime_since(&ss->prev_time, &now);
		memcpy(&ss->prev_time, &now, sizeof(now));

		/* 
		 * Begin monitoring when job starts but don't actually use
		 * data in checking stopping criterion until ss->ramp_time is
		 * over. This ensures that we will have a sane value in
		 * prev_iops/bw the first time through after ss->ramp_time
		 * is done.
		 */
		if (ss->ramp_time_over) {
			group_bw += 1000 * (td_bytes - ss->prev_bytes) / rate_time;
	        	group_iops += 1000 * (td_iops - ss->prev_iops) / rate_time;
			++group_ramp_time_over;
		}
		ss->prev_iops = td_iops;
		ss->prev_bytes = td_bytes;

		if (td->o.group_reporting && !ss->last_in_group)
			continue;

		/* don't begin checking criterion until ss->ramp_time is over for at least one thread in group */
		if (!group_ramp_time_over)
			continue;

		dprint(FD_STEADYSTATE, "steadystate_check() thread: %d, groupid: %u, rate_msec: %ld, iops: %lu, bw: %lu, head: %d, tail: %d\n", 
			i, td->groupid, rate_time, group_iops, group_bw, ss->head, ss->tail);

		if (ss->evaluate(group_iops, group_bw, td))
		{
			if (td->o.group_reporting)
				for_each_td(td2, j) {
					if (td2->groupid == td->groupid) {
						td2->ss.attained = 1;
						fio_mark_td_terminate(td2);
					}
				}
			else {
				ss->attained = 1;
				fio_mark_td_terminate(td);
			}
		}
	}
}

bool steadystate_slope(unsigned long iops, unsigned long bw, struct thread_data *td)
{
	int i, x;
	double result;
	double slope;
	struct steadystate_data *ss = &td->ss;

	ss->cache[ss->tail] = ss->check_iops ? iops : bw;

	if (ss->tail < ss->head || (ss->tail - ss->head == ss->dur - 1))
	{
		if (ss->sum_y == 0)	/* first time through */
		{
			for(i = 0; i < ss->dur; i++)
			{
				ss->sum_y += ss->cache[i];
				x = ss->head + i;
				if (x >= ss->dur)
					x -= ss->dur;
				ss->sum_xy += ss->cache[x] * i;
			}
		} else {		/* easy to update the sums */
			ss->sum_y -= ss->oldest_y;
			ss->sum_y += ss->cache[ss->tail];
			ss->sum_xy = ss->sum_xy - ss->sum_y + ss->dur * ss->cache[ss->tail];
		}

		ss->oldest_y = ss->cache[ss->head];

		/*
		 * calculate slope as (sum_xy - sum_x * sum_y / n) / (sum_(x^2) - (sum_x)^2 / n)
		 * This code assumes that all x values are equally spaced when they are often
		 * off by a few milliseconds. This assumption greatly simplifies the
		 * calculations.
		 */
		slope = (ss->sum_xy - (double) ss->sum_x * ss->sum_y / ss->dur) / (ss->sum_x_sq - (double) ss->sum_x * ss->sum_x / ss->dur);
		ss->criterion = ss->pct ? slope / (ss->sum_y / ss->dur) * 100.0: slope;

		dprint(FD_STEADYSTATE, "sum_y: %llu, sum_xy: %llu, slope: %f, criterion: %f, limit: %f\n",
			ss->sum_y, ss->sum_xy, slope, ss->criterion, ss->limit);

		result = ss->criterion * (ss->criterion < 0.0 ? -1 : 1);
		if (result < ss->limit)
			return true;
	}

	ss->tail = (ss->tail + 1) % ss->dur;
	if (ss->tail <= ss->head)
		ss->head = (ss->head + 1) % ss->dur;
	return false;
}

bool steadystate_deviation(unsigned long iops, unsigned long bw, struct thread_data *td)
{
	int i;
	double diff;
	double mean;
	double deviation;

	struct steadystate_data *ss = &td->ss;

	ss->cache[ss->tail] = ss->check_iops ? iops : bw;

	if (ss->tail < ss->head || (ss->tail - ss->head == ss->dur - 1))
	{
		if (ss->sum_y == 0)	/* first time through */
		{
			for(i = 0; i < ss->dur; i++)
				ss->sum_y += ss->cache[i];
		} else {		/* easy to update the sum */
			ss->sum_y -= ss->oldest_y;
			ss->sum_y += ss->cache[ss->tail];
		}

		ss->oldest_y = ss->cache[ss->head];
		mean = (double) ss->sum_y / ss->dur;
		deviation = 0.0;

		for (i = 0; i < ss->dur; i++)
		{	
			diff = (double) ss->cache[i] - mean;
			deviation = max(deviation, diff * (diff < 0.0 ? -1 : 1));
		}

		ss->criterion = ss->pct ? deviation / mean * 100.0 : deviation;

		dprint(FD_STEADYSTATE, "sum_y: %llu, mean: %f, max diff: %f, objective: %f, limit: %f\n", ss->sum_y, mean, deviation, ss->criterion, ss->limit);

		if (ss->criterion < ss->limit)
			return true;
	}

	ss->tail = (ss->tail + 1) % ss->dur;
	if (ss->tail <= ss->head)
		ss->head = (ss->head + 1) % ss->dur;
	return false;
}
