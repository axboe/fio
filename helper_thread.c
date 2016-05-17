#include "fio.h"
#include "smalloc.h"
#include "helper_thread.h"

static struct helper_data {
	volatile int exit;
	volatile int reset;
	volatile int do_stat;
	struct sk_out *sk_out;
	pthread_t thread;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct fio_mutex *startup_mutex;
} *helper_data;

void helper_thread_destroy(void)
{
	pthread_cond_destroy(&helper_data->cond);
	pthread_mutex_destroy(&helper_data->lock);
	sfree(helper_data);
}

void helper_reset(void)
{
	if (!helper_data)
		return;

	pthread_mutex_lock(&helper_data->lock);

	if (!helper_data->reset) {
		helper_data->reset = 1;
		pthread_cond_signal(&helper_data->cond);
	}

	pthread_mutex_unlock(&helper_data->lock);
}

void helper_do_stat(void)
{
	if (!helper_data)
		return;

	pthread_mutex_lock(&helper_data->lock);
	helper_data->do_stat = 1;
	pthread_cond_signal(&helper_data->cond);
	pthread_mutex_unlock(&helper_data->lock);
}

bool helper_should_exit(void)
{
	if (!helper_data)
		return true;

	return helper_data->exit;
}

void helper_thread_exit(void)
{
	void *ret;

	pthread_mutex_lock(&helper_data->lock);
	helper_data->exit = 1;
	pthread_cond_signal(&helper_data->cond);
	pthread_mutex_unlock(&helper_data->lock);

	pthread_join(helper_data->thread, &ret);
}

static void *helper_thread_main(void *data)
{
	struct helper_data *hd = data;
	unsigned int msec_to_next_event, next_log;
	struct timeval tv, last_du;
	int ret = 0;

	sk_out_assign(hd->sk_out);

	gettimeofday(&tv, NULL);
	memcpy(&last_du, &tv, sizeof(tv));

	fio_mutex_up(hd->startup_mutex);

	msec_to_next_event = DISK_UTIL_MSEC;
	while (!ret && !hd->exit) {
		struct timespec ts;
		struct timeval now;
		uint64_t since_du;

		timeval_add_msec(&tv, msec_to_next_event);
		ts.tv_sec = tv.tv_sec;
		ts.tv_nsec = tv.tv_usec * 1000;

		pthread_mutex_lock(&hd->lock);
		pthread_cond_timedwait(&hd->cond, &hd->lock, &ts);

		gettimeofday(&now, NULL);

		if (hd->reset) {
			memcpy(&tv, &now, sizeof(tv));
			memcpy(&last_du, &now, sizeof(last_du));
			hd->reset = 0;
		}

		pthread_mutex_unlock(&hd->lock);

		since_du = mtime_since(&last_du, &now);
		if (since_du >= DISK_UTIL_MSEC || DISK_UTIL_MSEC - since_du < 10) {
			ret = update_io_ticks();
			timeval_add_msec(&last_du, DISK_UTIL_MSEC);
			msec_to_next_event = DISK_UTIL_MSEC;
			if (since_du >= DISK_UTIL_MSEC)
				msec_to_next_event -= (since_du - DISK_UTIL_MSEC);
		} else {
			if (since_du >= DISK_UTIL_MSEC)
				msec_to_next_event = DISK_UTIL_MSEC - (DISK_UTIL_MSEC - since_du);
			else
				msec_to_next_event = DISK_UTIL_MSEC;
		}

		if (hd->do_stat) {
			hd->do_stat = 0;
			__show_running_run_stats();
		}

		next_log = calc_log_samples();
		if (!next_log)
			next_log = DISK_UTIL_MSEC;

		msec_to_next_event = min(next_log, msec_to_next_event);

		if (!is_backend)
			print_thread_status();
	}

	fio_writeout_logs(false);

	sk_out_drop();
	return NULL;
}

int helper_thread_create(struct fio_mutex *startup_mutex, struct sk_out *sk_out)
{
	struct helper_data *hd;
	int ret;

	hd = smalloc(sizeof(*hd));

	setup_disk_util();

	hd->sk_out = sk_out;
	pthread_cond_init(&hd->cond, NULL);
	pthread_mutex_init(&hd->lock, NULL);
	hd->startup_mutex = startup_mutex;

	ret = pthread_create(&hd->thread, NULL, helper_thread_main, hd);
	if (ret) {
		log_err("Can't create helper thread: %s\n", strerror(ret));
		return 1;
	}

	helper_data = hd;

	dprint(FD_MUTEX, "wait on startup_mutex\n");
	fio_mutex_down(startup_mutex);
	dprint(FD_MUTEX, "done waiting on startup_mutex\n");
	return 0;
}
