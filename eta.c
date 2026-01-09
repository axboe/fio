/*
 * Status and ETA code
 */
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#ifdef CONFIG_VALGRIND_DEV
#include <valgrind/drd.h>
#else
#define DRD_IGNORE_VAR(x) do { } while (0)
#endif

#include "fio.h"
#include "lib/pow2.h"

static char __run_str[REAL_MAX_JOBS + 1];
static char run_str[__THREAD_RUNSTR_SZ(REAL_MAX_JOBS) + 1];

static void update_condensed_str(char *rstr, char *run_str_condensed)
{
	if (*rstr) {
		while (*rstr) {
			int nr = 1;

			*run_str_condensed++ = *rstr++;
			while (*(rstr - 1) == *rstr) {
				rstr++;
				nr++;
			}
			run_str_condensed += sprintf(run_str_condensed, "(%u),", nr);
		}
		run_str_condensed--;
	}
	*run_str_condensed = '\0';
}

/*
 * Sets the status of the 'td' in the printed status map.
 */
static void check_str_update(struct thread_data *td)
{
	char c = __run_str[td->thread_number - 1];

	switch (td->runstate) {
	case TD_REAPED:
		if (td->error)
			c = 'X';
		else if (td->sig)
			c = 'K';
		else
			c = '_';
		break;
	case TD_EXITED:
		c = 'E';
		break;
	case TD_RAMP:
		c = '/';
		break;
	case TD_RUNNING:
		if (td_rw(td)) {
			if (td_random(td)) {
				if (td->o.rwmix[DDIR_READ] == 100)
					c = 'r';
				else if (td->o.rwmix[DDIR_WRITE] == 100)
					c = 'w';
				else
					c = 'm';
			} else {
				if (td->o.rwmix[DDIR_READ] == 100)
					c = 'R';
				else if (td->o.rwmix[DDIR_WRITE] == 100)
					c = 'W';
				else
					c = 'M';
			}
		} else if (td_read(td)) {
			if (td_random(td))
				c = 'r';
			else
				c = 'R';
		} else if (td_write(td)) {
			if (td_random(td))
				c = 'w';
			else
				c = 'W';
		} else {
			if (td_random(td))
				c = 'd';
			else
				c = 'D';
		}
		break;
	case TD_PRE_READING:
		c = 'p';
		break;
	case TD_VERIFYING:
		c = 'V';
		break;
	case TD_FSYNCING:
		c = 'F';
		break;
	case TD_FINISHING:
		c = 'f';
		break;
	case TD_CREATED:
		c = 'C';
		break;
	case TD_INITIALIZED:
	case TD_SETTING_UP:
		c = 'I';
		break;
	case TD_NOT_CREATED:
		c = 'P';
		break;
	default:
		log_err("state %d\n", td->runstate);
	}

	__run_str[td->thread_number - 1] = c;
	update_condensed_str(__run_str, run_str);
}

/*
 * Convert seconds to a printable string.
 */
void eta_to_str(char *str, unsigned long eta_sec)
{
	unsigned int d, h, m, s;
	int disp_hour = 0;

	if (eta_sec == -1) {
		sprintf(str, "--");
		return;
	}

	s = eta_sec % 60;
	eta_sec /= 60;
	m = eta_sec % 60;
	eta_sec /= 60;
	h = eta_sec % 24;
	eta_sec /= 24;
	d = eta_sec;

	if (d) {
		disp_hour = 1;
		str += sprintf(str, "%02ud:", d);
	}

	if (h || disp_hour)
		str += sprintf(str, "%02uh:", h);

	str += sprintf(str, "%02um:", m);
	sprintf(str, "%02us", s);
}

/*
 * Best effort calculation of the estimated pending runtime of a job.
 */
static unsigned long thread_eta(struct thread_data *td)
{
	unsigned long long bytes_total, bytes_done;
	unsigned long eta_sec = 0;
	unsigned long elapsed;
	uint64_t timeout;

	elapsed = (mtime_since_now(&td->epoch) + 999) / 1000;
	timeout = td->o.timeout / 1000000UL;

	bytes_total = td->total_io_size;

	if (td->flags & TD_F_NO_PROGRESS)
		return -1;

	if (td->o.fill_device && td->o.size  == -1ULL) {
		if (!td->fill_device_size || td->fill_device_size == -1ULL)
			return 0;

		bytes_total = td->fill_device_size;
	}

	/*
	 * If io_size is set, bytes_total is an exact value that does not need
	 * adjustment.
	 */
	if (td->o.zone_size && td->o.zone_skip && bytes_total &&
	    !fio_option_is_set(&td->o, io_size)) {
		unsigned int nr_zones;
		uint64_t zone_bytes;

		/*
		 * Calculate the upper bound of the number of zones that will
		 * be processed, including skipped bytes between zones. If this
		 * is larger than total_io_size (e.g. when --io_size or --size
		 * specify a small value), use the lower bound to avoid
		 * adjustments to a negative value that would result in a very
		 * large bytes_total and an incorrect eta.
		 */
		zone_bytes = td->o.zone_size + td->o.zone_skip;
		nr_zones = (bytes_total + zone_bytes - 1) / zone_bytes;
		if (bytes_total < nr_zones * td->o.zone_skip)
			nr_zones = bytes_total / zone_bytes;
		bytes_total -= nr_zones * td->o.zone_skip;
	}

	/*
	 * if writing and verifying afterwards, bytes_total will be twice the
	 * size. In a mixed workload, verify phase will be the size of the
	 * first stage writes.
	 */
	if (td->o.do_verify && td->o.verify && td_write(td)) {
		if (td_rw(td)) {
			unsigned int perc = 50;

			if (td->o.rwmix[DDIR_WRITE])
				perc = td->o.rwmix[DDIR_WRITE];

			bytes_total += (bytes_total * perc) / 100;
		} else {
			bytes_total <<= 1;
		}
	}

	if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING) {
		double perc, perc_t;

		bytes_done = ddir_rw_sum(td->io_bytes);

		if (bytes_total) {
			perc = (double) bytes_done / (double) bytes_total;
			if (perc > 1.0)
				perc = 1.0;
		} else {
			perc = 0.0;
		}

		if (td->o.time_based) {
			if (timeout) {
				perc_t = (double) elapsed / (double) timeout;
				if (perc_t < perc)
					perc = perc_t;
			} else {
				/*
				 * Will never hit, we can't have time_based
				 * without a timeout set.
				 */
				perc = 0.0;
			}
		}

		if (perc == 0.0) {
			eta_sec = timeout;
		} else {
			eta_sec = (unsigned long) (elapsed * (1.0 / perc)) - elapsed;
		}

		if (td->o.timeout &&
		    eta_sec > (timeout + done_secs - elapsed))
			eta_sec = timeout + done_secs - elapsed;
	} else if (td->runstate == TD_NOT_CREATED || td->runstate == TD_CREATED
			|| td->runstate == TD_INITIALIZED
			|| td->runstate == TD_SETTING_UP
			|| td->runstate == TD_RAMP
			|| td->runstate == TD_PRE_READING) {
		int64_t t_eta = 0, r_eta = 0;
		unsigned long long rate_bytes;

		/*
		 * We can only guess - assume it'll run the full timeout
		 * if given, otherwise assume it'll run at the specified rate.
		 */
		if (td->o.timeout) {
			uint64_t __timeout = td->o.timeout;
			uint64_t start_delay = td->o.start_delay;
			uint64_t ramp_time = td->o.ramp_time;

			t_eta = __timeout + start_delay;
			if (in_ramp_period(td))
				t_eta += ramp_time;
			t_eta /= 1000000ULL;

			if ((td->runstate == TD_RAMP) && in_ramp_period(td)) {
				unsigned long ramp_left;

				ramp_left = mtime_since_now(&td->epoch);
				ramp_left = (ramp_left + 999) / 1000;
				if (ramp_left <= t_eta)
					t_eta -= ramp_left;
			}
		}
		rate_bytes = 0;
		if (td_read(td))
			rate_bytes  = td->o.rate[DDIR_READ];
		if (td_write(td))
			rate_bytes += td->o.rate[DDIR_WRITE];
		if (td_trim(td))
			rate_bytes += td->o.rate[DDIR_TRIM];

		if (rate_bytes) {
			r_eta = bytes_total / rate_bytes;
			r_eta += (td->o.start_delay / 1000000ULL);
		}

		if (r_eta && t_eta)
			eta_sec = min(r_eta, t_eta);
		else if (r_eta)
			eta_sec = r_eta;
		else if (t_eta)
			eta_sec = t_eta;
		else
			eta_sec = 0;
	} else {
		/*
		 * thread is already done or waiting for fsync
		 */
		eta_sec = 0;
	}

	return eta_sec;
}

static void calc_rate(int unified_rw_rep, unsigned long mtime,
		      unsigned long long *io_bytes,
		      unsigned long long *prev_io_bytes, uint64_t *rate)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		unsigned long long diff, this_rate;

		diff = io_bytes[i] - prev_io_bytes[i];
		if (mtime)
			this_rate = ((1000 * diff) / mtime) / 1024; /* KiB/s */
		else
			this_rate = 0;

		if (unified_rw_rep == UNIFIED_MIXED) {
			rate[i] = 0;
			rate[0] += this_rate;
		} else
			rate[i] = this_rate;

		prev_io_bytes[i] = io_bytes[i];
	}
}

static void calc_iops(int unified_rw_rep, unsigned long mtime,
		      unsigned long long *io_iops,
		      unsigned long long *prev_io_iops, unsigned int *iops)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		unsigned long long diff, this_iops;

		diff = io_iops[i] - prev_io_iops[i];
		if (mtime)
			this_iops = (diff * 1000) / mtime;
		else
			this_iops = 0;

		if (unified_rw_rep == UNIFIED_MIXED) {
			iops[i] = 0;
			iops[0] += this_iops;
		} else
			iops[i] = this_iops;

		prev_io_iops[i] = io_iops[i];
	}
}

/*
 * Allow a little slack - if we're within 95% of the time, allow ETA.
 */
bool eta_time_within_slack(unsigned int time)
{
	return time > ((eta_interval_msec * 95) / 100);
}

/*
 * These are the conditions under which we might be able to skip the eta
 * calculation.
 */
static bool skip_eta(void)
{
	if (!(output_format & FIO_OUTPUT_NORMAL) && f_out == stdout)
		return true;
	if (temp_stall_ts || eta_print == FIO_ETA_NEVER)
		return true;
	if (!isatty(STDOUT_FILENO) && eta_print != FIO_ETA_ALWAYS)
		return true;

	return false;
}

/*
 * Print status of the jobs we know about. This includes rate estimates,
 * ETA, thread state, etc.
 */
static bool calc_thread_status(struct jobs_eta *je, int force)
{
	int unified_rw_rep;
	bool any_td_in_ramp;
	uint64_t rate_time, disp_time, bw_avg_time, *eta_secs;
	unsigned long long io_bytes[DDIR_RWDIR_CNT] = {};
	unsigned long long io_iops[DDIR_RWDIR_CNT] = {};
	struct timespec now;

	static unsigned long long rate_io_bytes[DDIR_RWDIR_CNT];
	static unsigned long long disp_io_bytes[DDIR_RWDIR_CNT];
	static unsigned long long disp_io_iops[DDIR_RWDIR_CNT];
	static struct timespec rate_prev_time, disp_prev_time;

	bool ret = true;

	if (!force && skip_eta()) {
		if (write_bw_log)
			ret = false;
		else
			return false;
	}

	if (!ddir_rw_sum(rate_io_bytes))
		fill_start_time(&rate_prev_time);
	if (!ddir_rw_sum(disp_io_bytes))
		fill_start_time(&disp_prev_time);

	eta_secs = calloc(thread_number, sizeof(uint64_t));

	je->elapsed_sec = (mtime_since_genesis() + 999) / 1000;

	bw_avg_time = ULONG_MAX;
	unified_rw_rep = 0;
	for_each_td(td) {
		unified_rw_rep += td->o.unified_rw_rep;
		if (is_power_of_2(td->o.kb_base))
			je->is_pow2 = 1;
		je->unit_base = td->o.unit_base;
		je->sig_figs = td->o.sig_figs;
		if (td->o.bw_avg_time < bw_avg_time)
			bw_avg_time = td->o.bw_avg_time;
		if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING
		    || td->runstate == TD_FSYNCING
		    || td->runstate == TD_PRE_READING
		    || td->runstate == TD_FINISHING) {
			je->nr_running++;
			if (td_read(td)) {
				je->t_rate[0] += td->o.rate[DDIR_READ];
				je->t_iops[0] += td->o.rate_iops[DDIR_READ];
				je->m_rate[0] += td->o.ratemin[DDIR_READ];
				je->m_iops[0] += td->o.rate_iops_min[DDIR_READ];
			}
			if (td_write(td)) {
				je->t_rate[1] += td->o.rate[DDIR_WRITE];
				je->t_iops[1] += td->o.rate_iops[DDIR_WRITE];
				je->m_rate[1] += td->o.ratemin[DDIR_WRITE];
				je->m_iops[1] += td->o.rate_iops_min[DDIR_WRITE];
			}
			if (td_trim(td)) {
				je->t_rate[2] += td->o.rate[DDIR_TRIM];
				je->t_iops[2] += td->o.rate_iops[DDIR_TRIM];
				je->m_rate[2] += td->o.ratemin[DDIR_TRIM];
				je->m_iops[2] += td->o.rate_iops_min[DDIR_TRIM];
			}

			je->files_open += td->nr_open_files;
		} else if (td->runstate == TD_RAMP) {
			je->nr_running++;
			je->nr_ramp++;
		} else if (td->runstate == TD_SETTING_UP)
			je->nr_setting_up++;
		else if (td->runstate < TD_RUNNING)
			je->nr_pending++;

		if (je->elapsed_sec >= 3)
			eta_secs[__td_index] = thread_eta(td);
		else
			eta_secs[__td_index] = INT_MAX;

		check_str_update(td);

		if (td->runstate > TD_SETTING_UP) {
			int ddir;

			for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
				if (unified_rw_rep) {
					io_bytes[0] += td->io_bytes[ddir];
					io_iops[0] += td->io_blocks[ddir];
				} else {
					io_bytes[ddir] += td->io_bytes[ddir];
					io_iops[ddir] += td->io_blocks[ddir];
				}
			}
		}
	} end_for_each();

	if (exitall_on_terminate) {
		je->eta_sec = INT_MAX;
		for_each_td_index() {
			if (eta_secs[__td_index] < je->eta_sec)
				je->eta_sec = eta_secs[__td_index];
		} end_for_each();
	} else {
		unsigned long eta_stone = 0;

		je->eta_sec = 0;
		for_each_td(td) {
			if ((td->runstate == TD_NOT_CREATED) && td->o.stonewall)
				eta_stone += eta_secs[__td_index];
			else {
				if (eta_secs[__td_index] > je->eta_sec)
					je->eta_sec = eta_secs[__td_index];
			}
		} end_for_each();
		je->eta_sec += eta_stone;
	}

	free(eta_secs);

	fio_gettime(&now, NULL);
	rate_time = mtime_since(&rate_prev_time, &now);

	any_td_in_ramp = false;
	for_each_td(td) {
		any_td_in_ramp |= in_ramp_period(td);
	} end_for_each();
	if (write_bw_log && rate_time > bw_avg_time && !any_td_in_ramp) {
		calc_rate(unified_rw_rep, rate_time, io_bytes, rate_io_bytes,
				je->rate);
		memcpy(&rate_prev_time, &now, sizeof(now));
		regrow_agg_logs();
		for_each_rw_ddir(ddir) {
			add_agg_sample(sample_val(je->rate[ddir]), ddir, 0);
		}
	}

	disp_time = mtime_since(&disp_prev_time, &now);

	if (!force && !eta_time_within_slack(disp_time))
		return false;

	calc_rate(unified_rw_rep, disp_time, io_bytes, disp_io_bytes, je->rate);
	calc_iops(unified_rw_rep, disp_time, io_iops, disp_io_iops, je->iops);

	memcpy(&disp_prev_time, &now, sizeof(now));

	if (!force && !je->nr_running && !je->nr_pending)
		return false;

	je->nr_threads = thread_number;
	update_condensed_str(__run_str, run_str);
	memcpy(je->run_str, run_str, strlen(run_str));
	return ret;
}

static int gen_eta_str(struct jobs_eta *je, char *p, size_t left,
		       char **rate_str, char **iops_str)
{
	static const char c[DDIR_RWDIR_CNT] = {'r', 'w', 't'};
	bool has[DDIR_RWDIR_CNT];
	bool has_any = false;
	const char *sep;
	int l = 0;

	for_each_rw_ddir(ddir) {
		has[ddir] = (je->rate[ddir] || je->iops[ddir]);
		has_any |= has[ddir];
	}
	if (!has_any)
		return 0;

	l += snprintf(p + l, left - l, "[");
	sep = "";
	for_each_rw_ddir(ddir) {
		if (has[ddir]) {
			l += snprintf(p + l, left - l, "%s%c=%s",
					sep, c[ddir], rate_str[ddir]);
			sep = ",";
		}
	}
	l += snprintf(p + l, left - l, "][");
	sep = "";
	for_each_rw_ddir(ddir) {
		if (has[ddir]) {
			l += snprintf(p + l, left - l, "%s%c=%s",
					sep, c[ddir], iops_str[ddir]);
			sep = ",";
		}
	}
	l += snprintf(p + l, left - l, " IOPS]");

	return l;
}

void display_thread_status(struct jobs_eta *je)
{
	static struct timespec disp_eta_new_line;
	static int eta_new_line_init, eta_new_line_pending;
	static int linelen_last;
	static int eta_good;
	char output[__THREAD_RUNSTR_SZ(REAL_MAX_JOBS) + 512], *p = output;
	char eta_str[128];
	double perc = 0.0;

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	if (eta_new_line_pending) {
		eta_new_line_pending = 0;
		linelen_last = 0;
		p += sprintf(p, "\n");
	}

	p += sprintf(p, "Jobs: %d (f=%d)", je->nr_running, je->files_open);

	/* rate limits, if any */
	if (je->m_rate[0] || je->m_rate[1] || je->m_rate[2] ||
	    je->t_rate[0] || je->t_rate[1] || je->t_rate[2]) {
		char *tr, *mr;

		mr = num2str(je->m_rate[0] + je->m_rate[1] + je->m_rate[2],
				je->sig_figs, 1, je->is_pow2, N2S_BYTEPERSEC);
		tr = num2str(je->t_rate[0] + je->t_rate[1] + je->t_rate[2],
				je->sig_figs, 1, je->is_pow2, N2S_BYTEPERSEC);

		p += sprintf(p, ", %s-%s", mr, tr);
		free(tr);
		free(mr);
	} else if (je->m_iops[0] || je->m_iops[1] || je->m_iops[2] ||
		   je->t_iops[0] || je->t_iops[1] || je->t_iops[2]) {
		p += sprintf(p, ", %d-%d IOPS",
					je->m_iops[0] + je->m_iops[1] + je->m_iops[2],
					je->t_iops[0] + je->t_iops[1] + je->t_iops[2]);
	}

	/* current run string, % done, bandwidth, iops, eta */
	if (je->eta_sec != INT_MAX && je->nr_running) {
		char perc_str[32];
		char *iops_str[DDIR_RWDIR_CNT];
		char *rate_str[DDIR_RWDIR_CNT];
		size_t left;
		int l;
		int ddir;
		int linelen;

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running ||
		    je->eta_sec == -1)
			strcpy(perc_str, "-.-%");
		else {
			double mult = 100.0;

			if (je->nr_setting_up && je->nr_running)
				mult *= (1.0 - (double) je->nr_setting_up / (double) je->nr_running);

			eta_good = 1;
			perc *= mult;
			sprintf(perc_str, "%3.1f%%", perc);
		}

		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			rate_str[ddir] = num2str(je->rate[ddir], 4,
						1024, je->is_pow2, je->unit_base);
			iops_str[ddir] = num2str(je->iops[ddir], 4, 1, 0, N2S_NONE);
		}

		left = sizeof(output) - (p - output) - 1;
		l = snprintf(p, left, ": [%s][%s]", je->run_str, perc_str);
		l += gen_eta_str(je, p + l, left - l, rate_str, iops_str);
		l += snprintf(p + l, left - l, "[eta %s]", eta_str);

		/* If truncation occurred adjust l so p is on the null */
		if (l >= left)
			l = left - 1;
		p += l;
		linelen = p - output;
		if (l >= 0 && linelen < linelen_last)
			p += sprintf(p, "%*s", linelen_last - linelen, "");
		linelen_last = linelen;

		for (ddir = 0; ddir < DDIR_RWDIR_CNT; ddir++) {
			free(rate_str[ddir]);
			free(iops_str[ddir]);
		}
	}
	sprintf(p, "\r");

	printf("%s", output);

	if (!eta_new_line_init) {
		fio_gettime(&disp_eta_new_line, NULL);
		eta_new_line_init = 1;
	} else if (eta_new_line && mtime_since_now(&disp_eta_new_line) > eta_new_line) {
		fio_gettime(&disp_eta_new_line, NULL);
		eta_new_line_pending = 1;
	}

	fflush(stdout);
}

struct jobs_eta *get_jobs_eta(bool force, size_t *size)
{
	struct jobs_eta *je;

	if (!thread_number)
		return NULL;

	*size = sizeof(*je) + THREAD_RUNSTR_SZ + 8;
	je = calloc(1, *size);
	if (!je)
		return NULL;

	if (!calc_thread_status(je, force)) {
		free(je);
		return NULL;
	}

	*size = sizeof(*je) + strlen((char *) je->run_str) + 1;
	return je;
}

void print_thread_status(void)
{
	struct jobs_eta *je;
	size_t size;

	je = get_jobs_eta(false, &size);
	if (je) {
		display_thread_status(je);
		free(je);
	}
}

void print_status_init(int thr_number)
{
	struct jobs_eta_packed jep;

	compiletime_assert(sizeof(struct jobs_eta) == sizeof(jep), "jobs_eta");

	DRD_IGNORE_VAR(__run_str);
	__run_str[thr_number] = 'P';
	update_condensed_str(__run_str, run_str);
}
