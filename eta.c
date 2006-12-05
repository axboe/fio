/*
 * Status and ETA code
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "fio.h"
#include "os.h"

static char run_str[MAX_JOBS + 1];

/*
 * Sets the status of the 'td' in the printed status map.
 */
static void check_str_update(struct thread_data *td)
{
	char c = run_str[td->thread_number - 1];

	switch (td->runstate) {
		case TD_REAPED:
			c = '_';
			break;
		case TD_EXITED:
			c = 'E';
			break;
		case TD_RUNNING:
			if (td_rw(td)) {
				if (td->sequential)
					c = 'M';
				else
					c = 'm';
			} else if (td_read(td)) {
				if (td->sequential)
					c = 'R';
				else
					c = 'r';
			} else {
				if (td->sequential)
					c = 'W';
				else
					c = 'w';
			}
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
static void eta_to_str(char *str, int eta_sec)
{
	unsigned int d, h, m, s;
	static int always_d, always_h;

	d = h = m = s = 0;

	s = eta_sec % 60;
	eta_sec /= 60;
	m = eta_sec % 60;
	eta_sec /= 60;
	h = eta_sec % 24;
	eta_sec /= 24;
	d = eta_sec;

	if (d || always_d) {
		always_d = 1;
		str += sprintf(str, "%02ud:", d);
	}
	if (h || always_h) {
		always_h = 1;
		str += sprintf(str, "%02uh:", h);
	}

	str += sprintf(str, "%02um:", m);
	str += sprintf(str, "%02us", s);
}

/*
 * Best effort calculation of the estimated pending runtime of a job.
 */
static int thread_eta(struct thread_data *td, unsigned long elapsed)
{
	unsigned long long bytes_total, bytes_done;
	unsigned long eta_sec = 0;

	bytes_total = td->total_io_size;

	/*
	 * if writing, bytes_total will be twice the size. If mixing,
	 * assume a 50/50 split and thus bytes_total will be 50% larger.
	 */
	if (td->verify) {
		if (td_rw(td))
			bytes_total = bytes_total * 3 / 2;
		else
			bytes_total <<= 1;
	}

	if (td->zone_size && td->zone_skip)
		bytes_total /= (td->zone_skip / td->zone_size);

	if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING) {
		double perc;

		bytes_done = td->io_bytes[DDIR_READ] + td->io_bytes[DDIR_WRITE];
		perc = (double) bytes_done / (double) bytes_total;
		if (perc > 1.0)
			perc = 1.0;

		eta_sec = (unsigned long) (elapsed * (1.0 / perc)) - elapsed;

		if (td->timeout && eta_sec > (td->timeout - elapsed))
			eta_sec = td->timeout - elapsed;
	} else if (td->runstate == TD_NOT_CREATED || td->runstate == TD_CREATED
			|| td->runstate == TD_INITIALIZED) {
		int t_eta = 0, r_eta = 0;

		/*
		 * We can only guess - assume it'll run the full timeout
		 * if given, otherwise assume it'll run at the specified rate.
		 */
		if (td->timeout)
			t_eta = td->timeout + td->start_delay - elapsed;
		if (td->rate) {
			r_eta = (bytes_total / 1024) / td->rate;
			r_eta += td->start_delay - elapsed;
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

/*
 * Print status of the jobs we know about. This includes rate estimates,
 * ETA, thread state, etc.
 */
void print_thread_status(void)
{
	unsigned long elapsed = mtime_since_genesis() / 1000;
	int i, nr_running, nr_pending, t_rate, m_rate, *eta_secs, eta_sec;
	struct thread_data *td;
	char eta_str[32];
	double perc = 0.0;

	static unsigned long long prev_io_bytes[2];
	static struct timeval prev_time;
	static unsigned int r_rate, w_rate;
	unsigned long long io_bytes[2];
	unsigned long mtime;

	if (temp_stall_ts || terse_output)
		return;

	if (!prev_io_bytes[0] && !prev_io_bytes[1])
		fill_start_time(&prev_time);

	eta_secs = malloc(thread_number * sizeof(int));
	memset(eta_secs, 0, thread_number * sizeof(int));

	io_bytes[0] = io_bytes[1] = 0;
	nr_pending = nr_running = t_rate = m_rate = 0;
	for_each_td(td, i) {
		if (td->runstate == TD_RUNNING || td->runstate == TD_VERIFYING||
		    td->runstate == TD_FSYNCING) {
			nr_running++;
			t_rate += td->rate;
			m_rate += td->ratemin;
		} else if (td->runstate < TD_RUNNING)
			nr_pending++;

		if (elapsed >= 3)
			eta_secs[i] = thread_eta(td, elapsed);
		else
			eta_secs[i] = INT_MAX;

		check_str_update(td);
		io_bytes[0] += td->io_bytes[0];
		io_bytes[1] += td->io_bytes[1];
	}

	if (exitall_on_terminate)
		eta_sec = INT_MAX;
	else
		eta_sec = 0;

	for_each_td(td, i) {
		if (exitall_on_terminate) {
			if (eta_secs[i] < eta_sec)
				eta_sec = eta_secs[i];
		} else {
			if (eta_secs[i] > eta_sec)
				eta_sec = eta_secs[i];
		}
	}

	free(eta_secs);

	if (eta_sec != INT_MAX && elapsed) {
		perc = (double) elapsed / (double) (elapsed + eta_sec);
		eta_to_str(eta_str, eta_sec);
	}

	mtime = mtime_since_now(&prev_time);
	if (mtime > 1000) {
		r_rate = (io_bytes[0] - prev_io_bytes[0]) / mtime;
		w_rate = (io_bytes[1] - prev_io_bytes[1]) / mtime;
		fio_gettime(&prev_time, NULL);
		memcpy(prev_io_bytes, io_bytes, sizeof(io_bytes));
	}

	if (!nr_running && !nr_pending)
		return;

	printf("Threads running: %d", nr_running);
	if (m_rate || t_rate)
		printf(", commitrate %d/%dKiB/sec", t_rate, m_rate);
	if (eta_sec != INT_MAX && nr_running) {
		perc *= 100.0;
		printf(": [%s] [%3.2f%% done] [%6u/%6u kb/s] [eta %s]", run_str, perc, r_rate, w_rate, eta_str);
	}
	printf("\r");
	fflush(stdout);
}

void print_status_init(int thread_number)
{
	run_str[thread_number] = 'P';
}
