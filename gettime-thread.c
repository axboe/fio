#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>

#include "fio.h"
#include "smalloc.h"

struct timeval *fio_tv = NULL;
int fio_gtod_offload = 0;
static pthread_t gtod_thread;
static os_cpu_mask_t fio_gtod_cpumask;

void fio_gtod_init(void)
{
	if (fio_tv)
		return;

	fio_tv = smalloc(sizeof(struct timeval));
	if (!fio_tv)
		log_err("fio: smalloc pool exhausted\n");
}

static void fio_gtod_update(void)
{
	if (fio_tv) {
		struct timeval __tv;

		gettimeofday(&__tv, NULL);
		fio_tv->tv_sec = __tv.tv_sec;
		write_barrier();
		fio_tv->tv_usec = __tv.tv_usec;
		write_barrier();
	}
}

struct gtod_cpu_data {
	struct fio_mutex *mutex;
	unsigned int cpu;
};

static void *gtod_thread_main(void *data)
{
	struct fio_mutex *mutex = data;

	fio_setaffinity(gettid(), fio_gtod_cpumask);
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
	pthread_attr_setstacksize(&attr, 2 * PTHREAD_STACK_MIN);
	ret = pthread_create(&gtod_thread, &attr, gtod_thread_main, mutex);
	pthread_attr_destroy(&attr);
	if (ret) {
		log_err("Can't create gtod thread: %s\n", strerror(ret));
		goto err;
	}

	ret = pthread_detach(gtod_thread);
	if (ret) {
		log_err("Can't detach gtod thread: %s\n", strerror(ret));
		goto err;
	}

	dprint(FD_MUTEX, "wait on startup_mutex\n");
	fio_mutex_down(mutex);
	dprint(FD_MUTEX, "done waiting on startup_mutex\n");
err:
	fio_mutex_remove(mutex);
	return ret;
}

void fio_gtod_set_cpu(unsigned int cpu)
{
#ifdef FIO_HAVE_CPU_AFFINITY
	fio_cpu_set(&fio_gtod_cpumask, cpu);
#endif
}
