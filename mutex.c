#include <string.h>
#include <sys/mman.h>
#include <assert.h>

#include "log.h"
#include "mutex.h"
#include "pshared.h"
#include "os/os.h"
#include "fio_time.h"
#include "gettime.h"

void __fio_mutex_remove(struct fio_mutex *mutex)
{
	assert(mutex->magic == FIO_MUTEX_MAGIC);
	pthread_cond_destroy(&mutex->cond);

	/*
	 * Ensure any subsequent attempt to grab this mutex will fail
	 * with an assert, instead of just silently hanging.
	 */
	memset(mutex, 0, sizeof(*mutex));
}

void fio_mutex_remove(struct fio_mutex *mutex)
{
	__fio_mutex_remove(mutex);
	munmap((void *) mutex, sizeof(*mutex));
}

int __fio_mutex_init(struct fio_mutex *mutex, int value)
{
	int ret;

	mutex->value = value;
	mutex->magic = FIO_MUTEX_MAGIC;

	ret = mutex_cond_init_pshared(&mutex->lock, &mutex->cond);
	if (ret)
		return ret;

	return 0;
}

struct fio_mutex *fio_mutex_init(int value)
{
	struct fio_mutex *mutex = NULL;

	mutex = (void *) mmap(NULL, sizeof(struct fio_mutex),
				PROT_READ | PROT_WRITE,
				OS_MAP_ANON | MAP_SHARED, -1, 0);
	if (mutex == MAP_FAILED) {
		perror("mmap mutex");
		return NULL;
	}

	if (!__fio_mutex_init(mutex, value))
		return mutex;

	fio_mutex_remove(mutex);
	return NULL;
}

static bool mutex_timed_out(struct timespec *t, unsigned int msecs)
{
	struct timeval tv;
	struct timespec now;

	gettimeofday(&tv, NULL);
	now.tv_sec = tv.tv_sec;
	now.tv_nsec = tv.tv_usec * 1000;

	return mtime_since(t, &now) >= msecs;
}

int fio_mutex_down_timeout(struct fio_mutex *mutex, unsigned int msecs)
{
	struct timeval tv_s;
	struct timespec base;
	struct timespec t;
	int ret = 0;

	assert(mutex->magic == FIO_MUTEX_MAGIC);

	gettimeofday(&tv_s, NULL);
	base.tv_sec = t.tv_sec = tv_s.tv_sec;
	base.tv_nsec = t.tv_nsec = tv_s.tv_usec * 1000;

	t.tv_sec += msecs / 1000;
	t.tv_nsec += ((msecs * 1000000ULL) % 1000000000);
	if (t.tv_nsec >= 1000000000) {
		t.tv_nsec -= 1000000000;
		t.tv_sec++;
	}

	pthread_mutex_lock(&mutex->lock);

	mutex->waiters++;
	while (!mutex->value && !ret) {
		/*
		 * Some platforms (FreeBSD 9?) seems to return timed out
		 * way too early, double check.
		 */
		ret = pthread_cond_timedwait(&mutex->cond, &mutex->lock, &t);
		if (ret == ETIMEDOUT && !mutex_timed_out(&base, msecs))
			ret = 0;
	}
	mutex->waiters--;

	if (!ret) {
		mutex->value--;
		pthread_mutex_unlock(&mutex->lock);
		return 0;
	}

	pthread_mutex_unlock(&mutex->lock);
	return ret;
}

bool fio_mutex_down_trylock(struct fio_mutex *mutex)
{
	bool ret = true;

	assert(mutex->magic == FIO_MUTEX_MAGIC);

	pthread_mutex_lock(&mutex->lock);
	if (mutex->value) {
		mutex->value--;
		ret = false;
	}
	pthread_mutex_unlock(&mutex->lock);

	return ret;
}

void fio_mutex_down(struct fio_mutex *mutex)
{
	assert(mutex->magic == FIO_MUTEX_MAGIC);

	pthread_mutex_lock(&mutex->lock);

	while (!mutex->value) {
		mutex->waiters++;
		pthread_cond_wait(&mutex->cond, &mutex->lock);
		mutex->waiters--;
	}

	mutex->value--;
	pthread_mutex_unlock(&mutex->lock);
}

void fio_mutex_up(struct fio_mutex *mutex)
{
	int do_wake = 0;

	assert(mutex->magic == FIO_MUTEX_MAGIC);

	pthread_mutex_lock(&mutex->lock);
	read_barrier();
	if (!mutex->value && mutex->waiters)
		do_wake = 1;
	mutex->value++;

	if (do_wake)
		pthread_cond_signal(&mutex->cond);

	pthread_mutex_unlock(&mutex->lock);
}
