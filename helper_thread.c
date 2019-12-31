#ifdef CONFIG_VALGRIND_DEV
#include <valgrind/drd.h>
#else
#define DRD_IGNORE_VAR(x) do { } while (0)
#endif

#include "fio.h"
#include "smalloc.h"
#include "helper_thread.h"
#include "steadystate.h"
#include "pshared.h"

enum action {
	A_EXIT		= 1,
	A_RESET		= 2,
	A_DO_STAT	= 3,
};

static struct helper_data {
	volatile int exit;
	int pipe[2]; /* 0: read end; 1: write end. */
	struct sk_out *sk_out;
	pthread_t thread;
	struct fio_sem *startup_sem;
} *helper_data;

void helper_thread_destroy(void)
{
	close(helper_data->pipe[0]);
	close(helper_data->pipe[1]);
	sfree(helper_data);
}

static void submit_action(enum action a)
{
	const uint8_t data = a;
	int ret;

	if (!helper_data)
		return;

	ret = write(helper_data->pipe[1], &data, sizeof(data));
	assert(ret == 1);
}

void helper_reset(void)
{
	submit_action(A_RESET);
}

/*
 * May be invoked in signal handler context and hence must only call functions
 * that are async-signal-safe. See also
 * https://pubs.opengroup.org/onlinepubs/9699919799/functions/V2_chap02.html#tag_15_04_03.
 */
void helper_do_stat(void)
{
	submit_action(A_DO_STAT);
}

bool helper_should_exit(void)
{
	if (!helper_data)
		return true;

	return helper_data->exit;
}

void helper_thread_exit(void)
{
	helper_data->exit = 1;
	submit_action(A_EXIT);
	pthread_join(helper_data->thread, NULL);
}

static void *helper_thread_main(void *data)
{
	struct helper_data *hd = data;
	unsigned int msec_to_next_event, next_log, next_ss = STEADYSTATE_MSEC;
	struct timespec ts, last_du, last_ss;
	uint8_t action;
	int ret = 0;

	sk_out_assign(hd->sk_out);

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	clock_gettime(CLOCK_MONOTONIC, &ts);
#else
	clock_gettime(CLOCK_REALTIME, &ts);
#endif
	memcpy(&last_du, &ts, sizeof(ts));
	memcpy(&last_ss, &ts, sizeof(ts));

	fio_sem_up(hd->startup_sem);

	msec_to_next_event = DISK_UTIL_MSEC;
	while (!ret && !hd->exit) {
		uint64_t since_du, since_ss = 0;
		struct timeval timeout = {
			.tv_sec  = DISK_UTIL_MSEC / 1000,
			.tv_usec = (DISK_UTIL_MSEC % 1000) * 1000,
		};
		fd_set rfds, efds;

		timespec_add_msec(&ts, msec_to_next_event);

		if (read(hd->pipe[0], &action, sizeof(action)) < 0) {
			FD_ZERO(&rfds);
			FD_SET(hd->pipe[0], &rfds);
			FD_ZERO(&efds);
			FD_SET(hd->pipe[0], &efds);
			select(1, &rfds, NULL, &efds, &timeout);
			if (read(hd->pipe[0], &action, sizeof(action)) < 0)
				action = 0;
		}

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
		clock_gettime(CLOCK_MONOTONIC, &ts);
#else
		clock_gettime(CLOCK_REALTIME, &ts);
#endif

		if (action == A_RESET) {
			last_du = ts;
			last_ss = ts;
		}

		since_du = mtime_since(&last_du, &ts);
		if (since_du >= DISK_UTIL_MSEC || DISK_UTIL_MSEC - since_du < 10) {
			ret = update_io_ticks();
			timespec_add_msec(&last_du, DISK_UTIL_MSEC);
			msec_to_next_event = DISK_UTIL_MSEC;
			if (since_du >= DISK_UTIL_MSEC)
				msec_to_next_event -= (since_du - DISK_UTIL_MSEC);
		} else
			msec_to_next_event = DISK_UTIL_MSEC - since_du;

		if (action == A_DO_STAT)
			__show_running_run_stats();

		next_log = calc_log_samples();
		if (!next_log)
			next_log = DISK_UTIL_MSEC;

		if (steadystate_enabled) {
			since_ss = mtime_since(&last_ss, &ts);
			if (since_ss >= STEADYSTATE_MSEC || STEADYSTATE_MSEC - since_ss < 10) {
				steadystate_check();
				timespec_add_msec(&last_ss, since_ss);
				if (since_ss > STEADYSTATE_MSEC)
					next_ss = STEADYSTATE_MSEC - (since_ss - STEADYSTATE_MSEC);
				else
					next_ss = STEADYSTATE_MSEC;
			} else
				next_ss = STEADYSTATE_MSEC - since_ss;
                }

		msec_to_next_event = min(min(next_log, msec_to_next_event), next_ss);
		dprint(FD_HELPERTHREAD, "since_ss: %llu, next_ss: %u, next_log: %u, msec_to_next_event: %u\n", (unsigned long long)since_ss, next_ss, next_log, msec_to_next_event);

		if (!is_backend)
			print_thread_status();
	}

	fio_writeout_logs(false);

	sk_out_drop();
	return NULL;
}

int helper_thread_create(struct fio_sem *startup_sem, struct sk_out *sk_out)
{
	struct helper_data *hd;
	int ret;

	hd = scalloc(1, sizeof(*hd));

	setup_disk_util();
	steadystate_setup();

	hd->sk_out = sk_out;

#ifdef __linux__
	ret = pipe2(hd->pipe, O_CLOEXEC);
#else
	ret = pipe(hd->pipe);
#endif
	if (ret)
		return 1;

	ret = fcntl(hd->pipe[0], F_SETFL, O_NONBLOCK);
	assert(ret >= 0);

	hd->startup_sem = startup_sem;

	DRD_IGNORE_VAR(helper_data);

	ret = pthread_create(&hd->thread, NULL, helper_thread_main, hd);
	if (ret) {
		log_err("Can't create helper thread: %s\n", strerror(ret));
		return 1;
	}

	helper_data = hd;

	dprint(FD_MUTEX, "wait on startup_sem\n");
	fio_sem_down(startup_sem);
	dprint(FD_MUTEX, "done waiting on startup_sem\n");
	return 0;
}
