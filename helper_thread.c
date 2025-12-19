#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#ifdef CONFIG_HAVE_TIMERFD_CREATE
#include <sys/timerfd.h>
#endif
#ifdef CONFIG_VALGRIND_DEV
#include <valgrind/drd.h>
#else
#define DRD_IGNORE_VAR(x) do { } while (0)
#endif

#ifdef WIN32
#include "os/os-windows.h"
#endif

#include "fio.h"
#include "smalloc.h"
#include "helper_thread.h"
#include "steadystate.h"
#include "pshared.h"

static int sleep_accuracy_ms;
static int timerfd = -1;

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

struct interval_timer {
	const char	*name;
	struct timespec	expires;
	uint32_t	interval_ms;
	int		(*func)(void);
};

void helper_thread_destroy(void)
{
	if (!helper_data)
		return;

	close(helper_data->pipe[0]);
	close(helper_data->pipe[1]);
	sfree(helper_data);
}

#ifdef _WIN32
static void sock_init(void)
{
	WSADATA wsaData;
	int res;

	/* It is allowed to call WSAStartup() more than once. */
	res = WSAStartup(MAKEWORD(2, 2), &wsaData);
	assert(res == 0);
}

static int make_nonblocking(int fd)
{
	unsigned long arg = 1;

	return ioctlsocket(fd, FIONBIO, &arg);
}

static int write_to_pipe(int fd, const void *buf, size_t len)
{
	return send(fd, buf, len, 0);
}

static int read_from_pipe(int fd, void *buf, size_t len)
{
	return recv(fd, buf, len, 0);
}
#else
static void sock_init(void)
{
}

static int make_nonblocking(int fd)
{
	return fcntl(fd, F_SETFL, O_NONBLOCK);
}

static int write_to_pipe(int fd, const void *buf, size_t len)
{
	return write(fd, buf, len);
}

static int read_from_pipe(int fd, void *buf, size_t len)
{
	return read(fd, buf, len);
}
#endif

static void block_signals(void)
{
#ifdef CONFIG_PTHREAD_SIGMASK
	sigset_t sigmask;

	int ret;

	ret = pthread_sigmask(SIG_UNBLOCK, NULL, &sigmask);
	assert(ret == 0);
	ret = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
#endif
}

static void submit_action(enum action a)
{
	const char data = a;
	int ret;

	if (!helper_data)
		return;

	ret = write_to_pipe(helper_data->pipe[1], &data, sizeof(data));
	if (ret != 1) {
		log_err("failed to write action into pipe, err %i:%s", errno, strerror(errno));
		assert(0);
	}
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
	if (!helper_data)
		return;

	helper_data->exit = 1;
	pthread_join(helper_data->thread, NULL);
}

/* Resets timers and returns the time in milliseconds until the next event. */
static int reset_timers(struct interval_timer timer[], int num_timers,
			struct timespec *now)
{
	uint32_t msec_to_next_event = INT_MAX;
	int i;

	for (i = 0; i < num_timers; ++i) {
		timer[i].expires = *now;
		timespec_add_msec(&timer[i].expires, timer[i].interval_ms);
		msec_to_next_event = min_not_zero(msec_to_next_event,
						  timer[i].interval_ms);
	}

	return msec_to_next_event;
}

/*
 * Waits for an action from fd during at least timeout_ms. `fd` must be in
 * non-blocking mode.
 */
static uint8_t wait_for_action(int fd, unsigned int timeout_ms)
{
	struct timeval timeout = {
		.tv_sec  = timeout_ms / 1000,
		.tv_usec = (timeout_ms % 1000) * 1000,
	};
	fd_set rfds, efds;
	uint8_t action = 0;
	uint64_t exp;
	int res;

	res = read_from_pipe(fd, &action, sizeof(action));
	if (res > 0 || timeout_ms == 0)
		return action;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	FD_ZERO(&efds);
	FD_SET(fd, &efds);
#ifdef CONFIG_HAVE_TIMERFD_CREATE
	{
		/*
		 * If the timer frequency is 100 Hz, select() will round up
		 * `timeout` to the next multiple of 1 / 100 Hz = 10 ms. Hence
		 * use a high-resolution timer if possible to increase
		 * select() timeout accuracy.
		 */
		struct itimerspec delta = {};

		delta.it_value.tv_sec = timeout.tv_sec;
		delta.it_value.tv_nsec = timeout.tv_usec * 1000;
		res = timerfd_settime(timerfd, 0, &delta, NULL);
		assert(res == 0);
		FD_SET(timerfd, &rfds);
	}
#endif
	res = select(max(fd, timerfd) + 1, &rfds, NULL, &efds,
		     timerfd >= 0 ? NULL : &timeout);
	if (res < 0) {
		log_err("fio: select() call in helper thread failed: %s",
			strerror(errno));
		return A_EXIT;
	}
	if (FD_ISSET(fd, &rfds))
		read_from_pipe(fd, &action, sizeof(action));
	if (timerfd >= 0 && FD_ISSET(timerfd, &rfds)) {
		res = read(timerfd, &exp, sizeof(exp));
		assert(res == sizeof(exp));
	}
	return action;
}

/*
 * Verify whether or not timer @it has expired. If timer @it has expired, call
 * @it->func(). @now is the current time. @msec_to_next_event is an
 * input/output parameter that represents the time until the next event.
 */
static int eval_timer(struct interval_timer *it, const struct timespec *now,
		      unsigned int *msec_to_next_event)
{
	int64_t delta_ms;
	bool expired;

	/* interval == 0 means that the timer is disabled. */
	if (it->interval_ms == 0)
		return 0;

	delta_ms = rel_time_since(now, &it->expires);
	expired = delta_ms <= sleep_accuracy_ms;
	if (expired) {
		timespec_add_msec(&it->expires, it->interval_ms);
		delta_ms = rel_time_since(now, &it->expires);
		if (delta_ms < it->interval_ms - sleep_accuracy_ms ||
		    delta_ms > it->interval_ms + sleep_accuracy_ms) {
			dprint(FD_HELPERTHREAD,
			       "%s: delta = %" PRIi64 " <> %u. Clock jump?\n",
			       it->name, delta_ms, it->interval_ms);
			delta_ms = it->interval_ms;
			it->expires = *now;
			timespec_add_msec(&it->expires, it->interval_ms);
		}
	}
	*msec_to_next_event = min((unsigned int)delta_ms, *msec_to_next_event);
	return expired ? it->func() : 0;
}

static void *helper_thread_main(void *data)
{
	struct helper_data *hd = data;
	unsigned int msec_to_next_event, next_log;
	struct interval_timer timer[] = {
		{
			.name = "disk_util",
			.interval_ms = DISK_UTIL_MSEC,
			.func = update_io_ticks,
		},
		{
			.name = "status_interval",
			.interval_ms = status_interval,
			.func = __show_running_run_stats,
		},
		{
			.name = "steadystate",
			.interval_ms = steadystate_enabled ? ss_check_interval :
				0,
			.func = steadystate_check,
		},
		{
			.name = "ramp_period",
			.interval_ms = ramp_period_enabled ?
				RAMP_PERIOD_CHECK_MSEC : 0,
			.func = ramp_period_check,
		},
	};
	struct timespec ts;
	long clk_tck;
	int ret = 0;

	os_clk_tck(&clk_tck);

	dprint(FD_HELPERTHREAD, "clk_tck = %ld\n", clk_tck);
	assert(clk_tck > 0);
	sleep_accuracy_ms = (1000 + clk_tck - 1) / clk_tck;

#ifdef CONFIG_HAVE_TIMERFD_CREATE
	timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	assert(timerfd >= 0);
	sleep_accuracy_ms = 1;
#endif

	sk_out_assign(hd->sk_out);

	/* Let another thread handle signals. */
	block_signals();

	fio_get_mono_time(&ts);
	msec_to_next_event = reset_timers(timer, FIO_ARRAY_SIZE(timer), &ts);

	fio_sem_up(hd->startup_sem);

	while (!ret && !hd->exit) {
		uint8_t action;
		int i;

		action = wait_for_action(hd->pipe[0], msec_to_next_event);
		if (action == A_EXIT)
			break;

		fio_get_mono_time(&ts);

		msec_to_next_event = INT_MAX;

		if (action == A_RESET)
			msec_to_next_event = reset_timers(timer,
						FIO_ARRAY_SIZE(timer), &ts);

		for (i = 0; i < FIO_ARRAY_SIZE(timer); ++i)
			ret = eval_timer(&timer[i], &ts, &msec_to_next_event);

		if (action == A_DO_STAT)
			__show_running_run_stats();

		next_log = calc_log_samples();
		if (!next_log)
			next_log = DISK_UTIL_MSEC;

		msec_to_next_event = min(next_log, msec_to_next_event);
		dprint(FD_HELPERTHREAD,
		       "next_log: %u, msec_to_next_event: %u\n",
		       next_log, msec_to_next_event);

		if (!is_backend)
			print_thread_status();
	}

	if (timerfd >= 0) {
		close(timerfd);
		timerfd = -1;
	}

	fio_writeout_logs(false);

	sk_out_drop();
	return NULL;
}

/*
 * Connect two sockets to each other to emulate the pipe() system call on Windows.
 */
int pipe_over_loopback(int fd[2])
{
	struct sockaddr_in addr = { .sin_family = AF_INET };
	socklen_t len = sizeof(addr);
	int res;

	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	sock_init();

	fd[0] = socket(AF_INET, SOCK_STREAM, 0);
	if (fd[0] < 0)
		goto err;
	fd[1] = socket(AF_INET, SOCK_STREAM, 0);
	if (fd[1] < 0)
		goto close_fd_0;
	res = bind(fd[0], (struct sockaddr *)&addr, len);
	if (res < 0)
		goto close_fd_1;
	res = getsockname(fd[0], (struct sockaddr *)&addr, &len);
	if (res < 0)
		goto close_fd_1;
	res = listen(fd[0], 1);
	if (res < 0)
		goto close_fd_1;
	res = connect(fd[1], (struct sockaddr *)&addr, len);
	if (res < 0)
		goto close_fd_1;
	res = accept(fd[0], NULL, NULL);
	if (res < 0)
		goto close_fd_1;
	close(fd[0]);
	fd[0] = res;
	return 0;

close_fd_1:
	close(fd[1]);

close_fd_0:
	close(fd[0]);

err:
	return -1;
}

int helper_thread_create(struct fio_sem *startup_sem, struct sk_out *sk_out)
{
	struct helper_data *hd;
	int ret;

	hd = scalloc(1, sizeof(*hd));
	if (!hd)
		return 1;

	setup_disk_util();
	steadystate_setup();

	hd->sk_out = sk_out;

#if defined(CONFIG_PIPE2)
	ret = pipe2(hd->pipe, O_CLOEXEC);
#elif defined(CONFIG_PIPE)
	ret = pipe(hd->pipe);
#else
	ret = pipe_over_loopback(hd->pipe);
#endif
	if (ret)
		return 1;

	ret = make_nonblocking(hd->pipe[0]);
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
