/*
 * Status and ETA code
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "fio.h"

static char run_str[REAL_MAX_JOBS + 1];

/*
 * Sets the status of the 'td' in the printed status map.
 */
static void check_str_update(struct thread_data *td)
{
	char c = run_str[td->thread_number - 1];

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

	run_str[td->thread_number - 1] = c;
}

/*
 * Convert seconds to a printable string.
 */
void eta_to_str(char *str, unsigned long eta_sec)
{
	unsigned int d, h, m, s;
	int disp_hour = 0;

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
	str += sprintf(str, "%02us", s);
}

/*
 * Best effort calculation of the estimated pending runtime of a job.
 */
static int thread_eta(struct thread_data *td)
{
	unsigned long long bytes_total, bytes_done;
	unsigned long eta_sec = 0;
	unsigned long elapsed;
	uint64_t timeout;

	elapsed = (mtime_since_now(&td->epoch) + 999) / 1000;
	timeout = td->o.timeout / 1000000UL;

	bytes_total = td->total_io_size;

	if (td->o.fill_device && td->o.size  == -1ULL) {
		if (!td->fill_device_size || td->fill_device_size == -1ULL)
			return 0;

		bytes_total = td->fill_device_size;
	}

	if (td->o.zone_size && td->o.zone_skip && bytes_total) {
		unsigned int nr_zones;
		uint64_t zone_bytes;

		zone_bytes = bytes_total + td->o.zone_size + td->o.zone_skip;
		nr_zones = (zone_bytes - 1) / (td->o.zone_size + td->o.zone_skip);
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
		} else
			bytes_total <<= 1;
	}

	if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING) {
		double perc, perc_t;

		bytes_done = ddir_rw_sum(td->io_bytes);

		if (bytes_total) {
			perc = (double) bytes_done / (double) bytes_total;
			if (perc > 1.0)
				perc = 1.0;
		} else
			perc = 0.0;

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

		eta_sec = (unsigned long) (elapsed * (1.0 / perc)) - elapsed;

		if (td->o.timeout &&
		    eta_sec > (timeout + done_secs - elapsed))
			eta_sec = timeout + done_secs - elapsed;
	} else if (td->runstate == TD_NOT_CREATED || td->runstate == TD_CREATED
			|| td->runstate == TD_INITIALIZED
			|| td->runstate == TD_SETTING_UP
			|| td->runstate == TD_RAMP
			|| td->runstate == TD_PRE_READING) {
		int t_eta = 0, r_eta = 0;
		unsigned long long rate_bytes;

		/*
		 * We can only guess - assume it'll run the full timeout
		 * if given, otherwise assume it'll run at the specified rate.
		 */
		if (td->o.timeout) {
			uint64_t timeout = td->o.timeout;
			uint64_t start_delay = td->o.start_delay;
			uint64_t ramp_time = td->o.ramp_time;

			t_eta = timeout + start_delay + ramp_time;
			t_eta /= 1000000ULL;

			if (in_ramp_time(td)) {
				unsigned long ramp_left;

				ramp_left = mtime_since_now(&td->epoch);
				ramp_left = (ramp_left + 999) / 1000;
				if (ramp_left <= t_eta)
					t_eta -= ramp_left;
			}
		}
		rate_bytes = ddir_rw_sum(td->o.rate);
		if (rate_bytes) {
			r_eta = (bytes_total / 1024) / rate_bytes;
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
		      unsigned long long *prev_io_bytes, unsigned int *rate)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		unsigned long long diff;

		diff = io_bytes[i] - prev_io_bytes[i];
		if (unified_rw_rep) {
			rate[i] = 0;
			rate[0] += ((1000 * diff) / mtime) / 1024;
		} else
			rate[i] = ((1000 * diff) / mtime) / 1024;

		prev_io_bytes[i] = io_bytes[i];
	}
}

static void calc_iops(int unified_rw_rep, unsigned long mtime,
		      unsigned long long *io_iops,
		      unsigned long long *prev_io_iops, unsigned int *iops)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		unsigned long long diff;

		diff = io_iops[i] - prev_io_iops[i];
		if (unified_rw_rep) {
			iops[i] = 0;
			iops[0] += (diff * 1000) / mtime;
		} else
			iops[i] = (diff * 1000) / mtime;

		prev_io_iops[i] = io_iops[i];
	}
}

/*
 * Print status of the jobs we know about. This includes rate estimates,
 * ETA, thread state, etc.
 */
int calc_thread_status(struct jobs_eta *je, int force)
{
	struct thread_data *td;
	int i, unified_rw_rep;
	unsigned long rate_time, disp_time, bw_avg_time, *eta_secs;
	unsigned long long io_bytes[DDIR_RWDIR_CNT];
	unsigned long long io_iops[DDIR_RWDIR_CNT];
	struct timeval now;

	static unsigned long long rate_io_bytes[DDIR_RWDIR_CNT];
	static unsigned long long disp_io_bytes[DDIR_RWDIR_CNT];
	static unsigned long long disp_io_iops[DDIR_RWDIR_CNT];
	static struct timeval rate_prev_time, disp_prev_time;

	if (!force) {
		if (output_format != FIO_OUTPUT_NORMAL &&
		    f_out == stdout)
			return 0;
		if (temp_stall_ts || eta_print == FIO_ETA_NEVER)
			return 0;

		if (!isatty(STDOUT_FILENO) && (eta_print != FIO_ETA_ALWAYS))
			return 0;
	}

	if (!ddir_rw_sum(rate_io_bytes))
		fill_start_time(&rate_prev_time);
	if (!ddir_rw_sum(disp_io_bytes))
		fill_start_time(&disp_prev_time);

	eta_secs = malloc(thread_number * sizeof(unsigned long));
	memset(eta_secs, 0, thread_number * sizeof(unsigned long));

	je->elapsed_sec = (mtime_since_genesis() + 999) / 1000;

	io_bytes[DDIR_READ] = io_bytes[DDIR_WRITE] = io_bytes[DDIR_TRIM] = 0;
	io_iops[DDIR_READ] = io_iops[DDIR_WRITE] = io_iops[DDIR_TRIM] = 0;
	bw_avg_time = ULONG_MAX;
	unified_rw_rep = 0;
	for_each_td(td, i) {
		unified_rw_rep += td->o.unified_rw_rep;
		if (is_power_of_2(td->o.kb_base))
			je->is_pow2 = 1;
		je->unit_base = td->o.unit_base;
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
		} else if (td->runstate == TD_SETTING_UP) {
			je->nr_running++;
			je->nr_setting_up++;
		} else if (td->runstate < TD_RUNNING)
			je->nr_pending++;

		if (je->elapsed_sec >= 3)
			eta_secs[i] = thread_eta(td);
		else
			eta_secs[i] = INT_MAX;

		check_str_update(td);

		if (td->runstate > TD_SETTING_UP) {
			int ddir;

			for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
				if (unified_rw_rep) {
					io_bytes[0] += td->io_bytes[ddir];
					io_iops[0] += td->io_blocks[ddir];
				} else {
					io_bytes[ddir] += td->io_bytes[ddir];
					io_iops[ddir] += td->io_blocks[ddir];
				}
			}
		}
	}

	if (exitall_on_terminate)
		je->eta_sec = INT_MAX;
	else
		je->eta_sec = 0;

	for_each_td(td, i) {
		if (exitall_on_terminate) {
			if (eta_secs[i] < je->eta_sec)
				je->eta_sec = eta_secs[i];
		} else {
			if (eta_secs[i] > je->eta_sec)
				je->eta_sec = eta_secs[i];
		}
	}

	free(eta_secs);

	fio_gettime(&now, NULL);
	rate_time = mtime_since(&rate_prev_time, &now);

	if (write_bw_log && rate_time > bw_avg_time && !in_ramp_time(td)) {
		calc_rate(unified_rw_rep, rate_time, io_bytes, rate_io_bytes,
				je->rate);
		memcpy(&rate_prev_time, &now, sizeof(now));
		add_agg_sample(je->rate[DDIR_READ], DDIR_READ, 0);
		add_agg_sample(je->rate[DDIR_WRITE], DDIR_WRITE, 0);
		add_agg_sample(je->rate[DDIR_TRIM], DDIR_TRIM, 0);
	}

	disp_time = mtime_since(&disp_prev_time, &now);

	/*
	 * Allow a little slack, the target is to print it every 1000 msecs
	 */
	if (!force && disp_time < 900)
		return 0;

	calc_rate(unified_rw_rep, disp_time, io_bytes, disp_io_bytes, je->rate);
	calc_iops(unified_rw_rep, disp_time, io_iops, disp_io_iops, je->iops);

	memcpy(&disp_prev_time, &now, sizeof(now));

	if (!force && !je->nr_running && !je->nr_pending)
		return 0;

	je->nr_threads = thread_number;
	memcpy(je->run_str, run_str, thread_number * sizeof(char));
	return 1;
}

void display_thread_status(struct jobs_eta *je)
{
	static struct timeval disp_eta_new_line;
	static int eta_new_line_init, eta_new_line_pending;
	static int linelen_last;
	static int eta_good;
	char output[REAL_MAX_JOBS + 512], *p = output;
	char eta_str[128];
	double perc = 0.0;

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	if (eta_new_line_pending) {
		eta_new_line_pending = 0;
		p += sprintf(p, "\n");
	}

	p += sprintf(p, "Jobs: %d (f=%d)", je->nr_running, je->files_open);
	if (je->m_rate[0] || je->m_rate[1] || je->t_rate[0] || je->t_rate[1]) {
		char *tr, *mr;

		mr = num2str(je->m_rate[0] + je->m_rate[1], 4, 0, je->is_pow2, 8);
		tr = num2str(je->t_rate[0] + je->t_rate[1], 4, 0, je->is_pow2, 8);
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops[0] || je->m_iops[1] || je->t_iops[0] || je->t_iops[1]) {
		p += sprintf(p, ", CR=%d/%d IOPS",
					je->t_iops[0] + je->t_iops[1],
					je->m_iops[0] + je->m_iops[1]);
	}
	if (je->eta_sec != INT_MAX && je->nr_running) {
		char perc_str[32];
		char *iops_str[DDIR_RWDIR_CNT];
		char *rate_str[DDIR_RWDIR_CNT];
		size_t left;
		int l;
		int ddir;

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running)
			strcpy(perc_str, "-.-% done");
		else {
			double mult = 100.0;

			if (je->nr_setting_up && je->nr_running)
				mult *= (1.0 - (double) je->nr_setting_up / (double) je->nr_running);

			eta_good = 1;
			perc *= mult;
			sprintf(perc_str, "%3.1f%% done", perc);
		}

		for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
			rate_str[ddir] = num2str(je->rate[ddir], 5,
						1024, je->is_pow2, je->unit_base);
			iops_str[ddir] = num2str(je->iops[ddir], 4, 1, 0, 0);
		}

		left = sizeof(output) - (p - output) - 1;

		l = snprintf(p, left, ": [%s] [%s] [%s/%s/%s /s] [%s/%s/%s iops] [eta %s]",
				je->run_str, perc_str, rate_str[DDIR_READ],
				rate_str[DDIR_WRITE], rate_str[DDIR_TRIM],
				iops_str[DDIR_READ], iops_str[DDIR_WRITE],
				iops_str[DDIR_TRIM], eta_str);
		p += l;
		if (l >= 0 && l < linelen_last)
			p += sprintf(p, "%*s", linelen_last - l, "");
		linelen_last = l;

		for (ddir = DDIR_READ; ddir < DDIR_RWDIR_CNT; ddir++) {
			free(rate_str[ddir]);
			free(iops_str[ddir]);
		}
	}
	p += sprintf(p, "\r");

	printf("%s", output);

	if (!eta_new_line_init) {
		fio_gettime(&disp_eta_new_line, NULL);
		eta_new_line_init = 1;
	} else if (eta_new_line &&
		   mtime_since_now(&disp_eta_new_line) > eta_new_line * 1000) {
		fio_gettime(&disp_eta_new_line, NULL);
		eta_new_line_pending = 1;
	}

	fflush(stdout);
}

void print_thread_status(void)
{
	struct jobs_eta *je;
	size_t size;

	if (!thread_number)
		return;

	size = sizeof(*je) + thread_number * sizeof(char) + 1;
	je = malloc(size);
	memset(je, 0, size);

	if (calc_thread_status(je, 0))
		display_thread_status(je);

	free(je);
}

void print_status_init(int thr_number)
{
	run_str[thr_number] = 'P';
}
