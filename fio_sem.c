#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <assert.h>
#ifdef CONFIG_VALGRIND_DEV
#include <valgrind/valgrind.h>
#else
#define RUNNING_ON_VALGRIND 0
#endif

#include "fio_sem.h"
#include "pshared.h"
#include "os/os.h"
#include "fio_time.h"
#include "gettime.h"

void __fio_sem_remove(struct fio_sem *sem)
{
	assert(sem->magic == FIO_SEM_MAGIC);
	pthread_mutex_destroy(&sem->lock);
	pthread_cond_destroy(&sem->cond);

	/*
	 * When not running on Valgrind, ensure any subsequent attempt to grab
	 * this semaphore will fail with an assert, instead of just silently
	 * hanging. When running on Valgrind, let Valgrind detect
	 * use-after-free.
         */
	if (!RUNNING_ON_VALGRIND)
		memset(sem, 0, sizeof(*sem));
}

void fio_sem_remove(struct fio_sem *sem)
{
	__fio_sem_remove(sem);
	munmap((void *) sem, sizeof(*sem));
}

int __fio_sem_init(struct fio_sem *sem, int value)
{
	int ret;

	sem->value = value;
	/* Initialize .waiters explicitly for Valgrind. */
	sem->waiters = 0;
	sem->magic = FIO_SEM_MAGIC;

	ret = mutex_cond_init_pshared(&sem->lock, &sem->cond);
	if (ret)
		return ret;

	return 0;
}

struct fio_sem *fio_sem_init(int value)
{
	struct fio_sem *sem = NULL;

	sem = (void *) mmap(NULL, sizeof(struct fio_sem),
				PROT_READ | PROT_WRITE,
				OS_MAP_ANON | MAP_SHARED, -1, 0);
	if (sem == MAP_FAILED) {
		perror("mmap semaphore");
		return NULL;
	}

	if (!__fio_sem_init(sem, value))
		return sem;

	fio_sem_remove(sem);
	return NULL;
}

static bool sem_timed_out(struct timespec *t, unsigned int msecs)
{
	struct timeval tv;
	struct timespec now;

	gettimeofday(&tv, NULL);
	now.tv_sec = tv.tv_sec;
	now.tv_nsec = tv.tv_usec * 1000;

	return mtime_since(t, &now) >= msecs;
}

int fio_sem_down_timeout(struct fio_sem *sem, unsigned int msecs)
{
	struct timespec base;
	struct timespec t;
	int ret = 0;

	assert(sem->magic == FIO_SEM_MAGIC);

#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	clock_gettime(CLOCK_MONOTONIC, &t);
#else
	clock_gettime(CLOCK_REALTIME, &t);
#endif

	base = t;

	t.tv_sec += msecs / 1000;
	t.tv_nsec += ((msecs * 1000000ULL) % 1000000000);
	if (t.tv_nsec >= 1000000000) {
		t.tv_nsec -= 1000000000;
		t.tv_sec++;
	}

	pthread_mutex_lock(&sem->lock);

	sem->waiters++;
	while (!sem->value && !ret) {
		/*
		 * Some platforms (FreeBSD 9?) seems to return timed out
		 * way too early, double check.
		 */
		ret = pthread_cond_timedwait(&sem->cond, &sem->lock, &t);
		if (ret == ETIMEDOUT && !sem_timed_out(&base, msecs))
			ret = 0;
	}
	sem->waiters--;

	if (!ret) {
		sem->value--;
		pthread_mutex_unlock(&sem->lock);
		return 0;
	}

	pthread_mutex_unlock(&sem->lock);
	return ret;
}

bool fio_sem_down_trylock(struct fio_sem *sem)
{
	bool ret = true;

	assert(sem->magic == FIO_SEM_MAGIC);

	pthread_mutex_lock(&sem->lock);
	if (sem->value) {
		sem->value--;
		ret = false;
	}
	pthread_mutex_unlock(&sem->lock);

	return ret;
}

void fio_sem_down(struct fio_sem *sem)
{
	assert(sem->magic == FIO_SEM_MAGIC);

	pthread_mutex_lock(&sem->lock);

	while (!sem->value) {
		sem->waiters++;
		pthread_cond_wait(&sem->cond, &sem->lock);
		sem->waiters--;
	}

	sem->value--;
	pthread_mutex_unlock(&sem->lock);
}

void fio_sem_up(struct fio_sem *sem)
{
	int do_wake = 0;

	assert(sem->magic == FIO_SEM_MAGIC);

	pthread_mutex_lock(&sem->lock);
	read_barrier();
	if (!sem->value && sem->waiters)
		do_wake = 1;
	sem->value++;

	if (do_wake)
		pthread_cond_signal(&sem->cond);

	pthread_mutex_unlock(&sem->lock);
}
