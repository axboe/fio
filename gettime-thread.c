#include <sys/time.h>
#include <time.h>

#include "fio.h"
#include "lib/seqlock.h"
#include "smalloc.h"

struct fio_ts *fio_ts;
int fio_gtod_offload = 0;
static pthread_t gtod_thread;
static os_cpu_mask_t fio_gtod_cpumask;

void fio_gtod_init(void)
{
	if (fio_ts)
		return;

	fio_ts = smalloc(sizeof(*fio_ts));
}

static void fio_gtod_update(void)
{
	struct timeval __tv;

	if (!fio_ts)
		return;

	gettimeofday(&__tv, NULL);

	write_seqlock_begin(&fio_ts->seqlock);
	fio_ts->ts.tv_sec = __tv.tv_sec;
	fio_ts->ts.tv_nsec = __tv.tv_usec * 1000;
	write_seqlock_end(&fio_ts->seqlock);
}

struct gtod_cpu_data {
	struct fio_sem *sem;
	unsigned int cpu;
};

static void *gtod_thread_main(void *data)
{
	struct fio_sem *sem = data;
	int ret;

	ret = fio_setaffinity(gettid(), fio_gtod_cpumask);

	fio_sem_up(sem);

	if (ret == -1) {
		log_err("gtod: setaffinity failed\n");
		return NULL;
	}

	/*
	 * As long as we have jobs around, update the clock. It would be nice
	 * to have some way of NOT hammering that CPU with gettimeofday(),
	 * but I'm not sure what to use outside of a simple CPU nop to relax
	 * it - we don't want to lose precision.
	 */
	while (nr_segments) {
		fio_gtod_update();
		nop;
	}

	return NULL;
}

int fio_start_gtod_thread(void)
{
	struct fio_sem *sem;
	pthread_attr_t attr;
	int ret;

	sem = fio_sem_init(FIO_SEM_LOCKED);
	if (!sem)
		return 1;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 2 * PTHREAD_STACK_MIN);
	ret = pthread_create(&gtod_thread, &attr, gtod_thread_main, sem);
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

	dprint(FD_MUTEX, "wait on startup_sem\n");
	fio_sem_down(sem);
	dprint(FD_MUTEX, "done waiting on startup_sem\n");
err:
	fio_sem_remove(sem);
	return ret;
}

void fio_gtod_set_cpu(unsigned int cpu)
{
#ifdef FIO_HAVE_CPU_AFFINITY
	fio_cpu_set(&fio_gtod_cpumask, cpu);
#endif
}
