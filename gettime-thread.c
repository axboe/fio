#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "fio.h"
#include "smalloc.h"

struct timeval *fio_tv = NULL;
int fio_gtod_offload = 0;
int fio_gtod_cpu = -1;
static pthread_t gtod_thread;

void fio_gtod_init(void)
{
	fio_tv = smalloc(sizeof(struct timeval));
	if (!fio_tv)
		log_err("fio: smalloc pool exhausted\n");
}

static void fio_gtod_update(void)
{
	if (fio_tv)
		gettimeofday(fio_tv, NULL);
}

static void *gtod_thread_main(void *data)
{
	struct fio_mutex *mutex = data;

	fio_mutex_up(mutex);

	/*
	 * As long as we have jobs around, update the clock. It would be nice
	 * to have some way of NOT hammering that CPU with gettimeofday(),
	 * but I'm not sure what to use outside of a simple CPU nop to relax
	 * it - we don't want to lose precision.
	 */
	while (threads) {
		fio_gtod_update();
		nop;
	}

	return NULL;
}

int fio_start_gtod_thread(void)
{
	struct fio_mutex *mutex;
	pthread_attr_t attr;
	int ret;

	mutex = fio_mutex_init(FIO_MUTEX_LOCKED);
	if (!mutex)
		return 1;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);
	ret = pthread_create(&gtod_thread, &attr, gtod_thread_main, NULL);
	pthread_attr_destroy(&attr);
	if (ret) {
		log_err("Can't create gtod thread: %s\n", strerror(ret));
		goto err;
	}

	ret = pthread_detach(gtod_thread);
	if (ret) {
		log_err("Can't detatch gtod thread: %s\n", strerror(ret));
		goto err;
	}

	dprint(FD_MUTEX, "wait on startup_mutex\n");
	fio_mutex_down(mutex);
	dprint(FD_MUTEX, "done waiting on startup_mutex\n");
err:
	fio_mutex_remove(mutex);
	return ret;
}


