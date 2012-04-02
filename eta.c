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
		} else {
			if (td_random(td))
				c = 'w';
			else
				c = 'W';
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
	case TD_CREATED:
		c = 'C';
		break;
	case TD_INITIALIZED:
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
static void eta_to_str(char *str, unsigned long eta_sec)
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

	elapsed = (mtime_since_now(&td->epoch) + 999) / 1000;

	bytes_total = td->total_io_size;

	if (td->o.fill_device && td->o.size  == -1ULL) {
		if (!td->fill_device_size || td->fill_device_size == -1ULL)
			return 0;

		bytes_total = td->fill_device_size;
	}

	/*
	 * if writing, bytes_total will be twice the size. If mixing,
	 * assume a 50/50 split and thus bytes_total will be 50% larger.
	 */
	if (td->o.do_verify && td->o.verify && td_write(td)) {
		if (td_rw(td))
			bytes_total = bytes_total * 3 / 2;
		else
			bytes_total <<= 1;
	}

	if (td->o.zone_size && td->o.zone_skip)
		bytes_total /= (td->o.zone_skip / td->o.zone_size);

	if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING) {
		double perc, perc_t;

		bytes_done = td->io_bytes[DDIR_READ] + td->io_bytes[DDIR_WRITE];
		perc = (double) bytes_done / (double) bytes_total;
		if (perc > 1.0)
			perc = 1.0;

		if (td->o.time_based) {
			perc_t = (double) elapsed / (double) td->o.timeout;
			if (perc_t < perc)
				perc = perc_t;
		}

		eta_sec = (unsigned long) (elapsed * (1.0 / perc)) - elapsed;

		if (td->o.timeout &&
		    eta_sec > (td->o.timeout + done_secs - elapsed))
			eta_sec = td->o.timeout + done_secs - elapsed;
	} else if (td->runstate == TD_NOT_CREATED || td->runstate == TD_CREATED
			|| td->runstate == TD_INITIALIZED
			|| td->runstate == TD_RAMP
			|| td->runstate == TD_PRE_READING) {
		int t_eta = 0, r_eta = 0;

		/*
		 * We can only guess - assume it'll run the full timeout
		 * if given, otherwise assume it'll run at the specified rate.
		 */
		if (td->o.timeout) {
			t_eta = td->o.timeout + td->o.start_delay +
					td->o.ramp_time;

			if (in_ramp_time(td)) {
				unsigned long ramp_left;

				ramp_left = mtime_since_now(&td->epoch);
				ramp_left = (ramp_left + 999) / 1000;
				if (ramp_left <= t_eta)
					t_eta -= ramp_left;
			}
		}
		if (td->o.rate[0] || td->o.rate[1]) {
			r_eta = (bytes_total / 1024) /
					(td->o.rate[0] + td->o.rate[1]);
			r_eta += td->o.start_delay;
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

static void calc_rate(unsigned long mtime, unsigned long long *io_bytes,
		      unsigned long long *prev_io_bytes, unsigned int *rate)
{
	rate[0] = (io_bytes[0] - prev_io_bytes[0]) / mtime;
	rate[1] = (io_bytes[1] - prev_io_bytes[1]) / mtime;
	prev_io_bytes[0] = io_bytes[0];
	prev_io_bytes[1] = io_bytes[1];
}

static void calc_iops(unsigned long mtime, unsigned long long *io_iops,
		      unsigned long long *prev_io_iops, unsigned int *iops)
{
	iops[0] = ((io_iops[0] - prev_io_iops[0]) * 1000) / mtime;
	iops[1] = ((io_iops[1] - prev_io_iops[1]) * 1000) / mtime;
	prev_io_iops[0] = io_iops[0];
	prev_io_iops[1] = io_iops[1];
}

/*
 * Print status of the jobs we know about. This includes rate estimates,
 * ETA, thread state, etc.
 */
int calc_thread_status(struct jobs_eta *je, int force)
{
	struct thread_data *td;
	int i;
	unsigned long rate_time, disp_time, bw_avg_time, *eta_secs;
	unsigned long long io_bytes[2];
	unsigned long long io_iops[2];
	struct timeval now;

	static unsigned long long rate_io_bytes[2];
	static unsigned long long disp_io_bytes[2];
	static unsigned long long disp_io_iops[2];
	static struct timeval rate_prev_time, disp_prev_time;
	int i2p = 0;

	if (!force) {
		if (temp_stall_ts || terse_output || eta_print == FIO_ETA_NEVER)
			return 0;

		if (!isatty(STDOUT_FILENO) && (eta_print != FIO_ETA_ALWAYS))
			return 0;
	}

	if (!rate_io_bytes[0] && !rate_io_bytes[1])
		fill_start_time(&rate_prev_time);
	if (!disp_io_bytes[0] && !disp_io_bytes[1])
		fill_start_time(&disp_prev_time);

	eta_secs = malloc(thread_number * sizeof(unsigned long));
	memset(eta_secs, 0, thread_number * sizeof(unsigned long));

	je->elapsed_sec = (mtime_since_genesis() + 999) / 1000;

	io_bytes[0] = io_bytes[1] = 0;
	io_iops[0] = io_iops[1] = 0;
	bw_avg_time = ULONG_MAX;
	for_each_td(td, i) {
		if (td->o.bw_avg_time < bw_avg_time)
			bw_avg_time = td->o.bw_avg_time;
		if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING
		    || td->runstate == TD_FSYNCING
		    || td->runstate == TD_PRE_READING) {
			je->nr_running++;
			je->t_rate += td->o.rate[0] + td->o.rate[1];
			je->m_rate += td->o.ratemin[0] + td->o.ratemin[1];
			je->t_iops += td->o.rate_iops[0] + td->o.rate_iops[1];
			je->m_iops += td->o.rate_iops_min[0] +
					td->o.rate_iops_min[1];
			je->files_open += td->nr_open_files;
		} else if (td->runstate == TD_RAMP) {
			je->nr_running++;
			je->nr_ramp++;
		} else if (td->runstate < TD_RUNNING)
			je->nr_pending++;

		if (je->elapsed_sec >= 3)
			eta_secs[i] = thread_eta(td);
		else
			eta_secs[i] = INT_MAX;

		check_str_update(td);

		if (td->runstate > TD_RAMP) {
			io_bytes[0] += td->io_bytes[0];
			io_bytes[1] += td->io_bytes[1];
			io_iops[0] += td->io_blocks[0];
			io_iops[1] += td->io_blocks[1];
		}
	}

	if (exitall_on_terminate)
		je->eta_sec = INT_MAX;
	else
		je->eta_sec = 0;

	for_each_td(td, i) {
		if (!i2p && is_power_of_2(td->o.kb_base))
			i2p = 1;
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
		calc_rate(rate_time, io_bytes, rate_io_bytes, je->rate);
		memcpy(&rate_prev_time, &now, sizeof(now));
		add_agg_sample(je->rate[DDIR_READ], DDIR_READ, 0);
		add_agg_sample(je->rate[DDIR_WRITE], DDIR_WRITE, 0);
	}

	disp_time = mtime_since(&disp_prev_time, &now);

	/*
	 * Allow a little slack, the target is to print it every 1000 msecs
	 */
	if (!force && disp_time < 900)
		return 0;

	calc_rate(disp_time, io_bytes, disp_io_bytes, je->rate);
	calc_iops(disp_time, io_iops, disp_io_iops, je->iops);

	memcpy(&disp_prev_time, &now, sizeof(now));

	if (!force && !je->nr_running && !je->nr_pending)
		return 0;

	je->nr_threads = thread_number;
	memcpy(je->run_str, run_str, thread_number * sizeof(char));

	return 1;
}

void display_thread_status(struct jobs_eta *je)
{
	static int linelen_last;
	static int eta_good;
	char output[512], *p = output;
	char eta_str[128];
	double perc = 0.0;
	int i2p = 0;

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	p += sprintf(p, "Jobs: %d (f=%d)", je->nr_running, je->files_open);
	if (je->m_rate || je->t_rate) {
		char *tr, *mr;

		mr = num2str(je->m_rate, 4, 0, i2p);
		tr = num2str(je->t_rate, 4, 0, i2p);
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops || je->t_iops)
		p += sprintf(p, ", CR=%d/%d IOPS", je->t_iops, je->m_iops);
	if (je->eta_sec != INT_MAX && je->nr_running) {
		char perc_str[32];
		char *iops_str[2];
		char *rate_str[2];
		int l;

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running)
			strcpy(perc_str, "-.-% done");
		else {
			eta_good = 1;
			perc *= 100.0;
			sprintf(perc_str, "%3.1f%% done", perc);
		}

		rate_str[0] = num2str(je->rate[0], 5, 10, i2p);
		rate_str[1] = num2str(je->rate[1], 5, 10, i2p);

		iops_str[0] = num2str(je->iops[0], 4, 1, 0);
		iops_str[1] = num2str(je->iops[1], 4, 1, 0);

		l = sprintf(p, ": [%s] [%s] [%s/%s /s] [%s/%s iops] [eta %s]",
				je->run_str, perc_str, rate_str[0],
				rate_str[1], iops_str[0], iops_str[1], eta_str);
		p += l;
		if (l >= 0 && l < linelen_last)
			p += sprintf(p, "%*s", linelen_last - l, "");
		linelen_last = l;

		free(rate_str[0]);
		free(rate_str[1]);
		free(iops_str[0]);
		free(iops_str[1]);
	}
	p += sprintf(p, "\r");

	printf("%s", output);
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
