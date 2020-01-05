#include <signal.h>
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

static void submit_action(enum action a)
{
	const char data = a;
	int ret;

	if (!helper_data)
		return;

	ret = write_to_pipe(helper_data->pipe[1], &data, sizeof(data));
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
	if (!helper_data)
		return;

	helper_data->exit = 1;
	submit_action(A_EXIT);
	pthread_join(helper_data->thread, NULL);
}

static void *helper_thread_main(void *data)
{
	struct helper_data *hd = data;
	unsigned int msec_to_next_event, next_log, next_ss = STEADYSTATE_MSEC;
	struct timespec ts, last_du, last_ss;
	char action;
	int ret = 0;

	sk_out_assign(hd->sk_out);

#ifdef HAVE_PTHREAD_SIGMASK
	{
	sigset_t sigmask;

	/* Let another thread handle signals. */
	ret = pthread_sigmask(SIG_UNBLOCK, NULL, &sigmask);
	assert(ret == 0);
	ret = pthread_sigmask(SIG_BLOCK, &sigmask, NULL);
	assert(ret == 0);
	}
#endif

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

		if (read_from_pipe(hd->pipe[0], &action, sizeof(action)) < 0) {
			FD_ZERO(&rfds);
			FD_SET(hd->pipe[0], &rfds);
			FD_ZERO(&efds);
			FD_SET(hd->pipe[0], &efds);
			ret = select(1, &rfds, NULL, &efds, &timeout);
			if (ret < 0)
				log_err("fio: select() call in helper thread failed: %s",
					strerror(errno));
			if (read_from_pipe(hd->pipe[0], &action, sizeof(action)) <
			    0)
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
