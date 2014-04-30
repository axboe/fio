#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>
#include <assert.h>

#include "fio.h"
#include "log.h"
#include "mutex.h"
#include "arch/arch.h"
#include "os/os.h"
#include "helpers.h"
#include "fio_time.h"
#include "gettime.h"

void fio_mutex_remove(struct fio_mutex *mutex)
{
	assert(mutex->magic == FIO_MUTEX_MAGIC);
	pthread_cond_destroy(&mutex->cond);
	munmap((void *) mutex, sizeof(*mutex));
}

int __fio_mutex_init(struct fio_mutex *mutex, int value)
{
	pthread_mutexattr_t attr;
	pthread_condattr_t cond;
	int ret;

	mutex->value = value;
	mutex->magic = FIO_MUTEX_MAGIC;

	ret = pthread_mutexattr_init(&attr);
	if (ret) {
		log_err("pthread_mutexattr_init: %s\n", strerror(ret));
		return ret;
	}

	/*
	 * Not all platforms support process shared mutexes (FreeBSD)
	 */
#ifdef FIO_HAVE_PSHARED_MUTEX
	ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_mutexattr_setpshared: %s\n", strerror(ret));
		return ret;
	}
#endif

	pthread_condattr_init(&cond);
#ifdef FIO_HAVE_PSHARED_MUTEX
	pthread_condattr_setpshared(&cond, PTHREAD_PROCESS_SHARED);
#endif
	pthread_cond_init(&mutex->cond, &cond);

	ret = pthread_mutex_init(&mutex->lock, &attr);
	if (ret) {
		log_err("pthread_mutex_init: %s\n", strerror(ret));
		return ret;
	}

	pthread_condattr_destroy(&cond);
	pthread_mutexattr_destroy(&attr);
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

static int mutex_timed_out(struct timeval *t, unsigned int seconds)
{
	return mtime_since_now(t) >= seconds * 1000;
}

int fio_mutex_down_timeout(struct fio_mutex *mutex, unsigned int seconds)
{
	struct timeval tv_s;
	struct timespec t;
	int ret = 0;

	assert(mutex->magic == FIO_MUTEX_MAGIC);

	gettimeofday(&tv_s, NULL);
	t.tv_sec = tv_s.tv_sec + seconds;
	t.tv_nsec = tv_s.tv_usec * 1000;

	pthread_mutex_lock(&mutex->lock);

	while (!mutex->value && !ret) {
		mutex->waiters++;

		/*
		 * Some platforms (FreeBSD 9?) seems to return timed out
		 * way too early, double check.
		 */
		ret = pthread_cond_timedwait(&mutex->cond, &mutex->lock, &t);
		if (ret == ETIMEDOUT && !mutex_timed_out(&tv_s, seconds))
			ret = 0;

		mutex->waiters--;
	}

	if (!ret) {
		mutex->value--;
		pthread_mutex_unlock(&mutex->lock);
	}

	return ret;
}

int fio_mutex_down_trylock(struct fio_mutex *mutex)
{
	int ret = 1;

	assert(mutex->magic == FIO_MUTEX_MAGIC);

	pthread_mutex_lock(&mutex->lock);
	if (mutex->value) {
		mutex->value--;
		ret = 0;
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
	assert(mutex->magic == FIO_MUTEX_MAGIC);

	pthread_mutex_lock(&mutex->lock);
	read_barrier();
	if (!mutex->value && mutex->waiters)
		pthread_cond_signal(&mutex->cond);
	mutex->value++;
	pthread_mutex_unlock(&mutex->lock);
}

void fio_rwlock_write(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_wrlock(&lock->lock);
}

void fio_rwlock_read(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_rdlock(&lock->lock);
}

void fio_rwlock_unlock(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	pthread_rwlock_unlock(&lock->lock);
}

void fio_rwlock_remove(struct fio_rwlock *lock)
{
	assert(lock->magic == FIO_RWLOCK_MAGIC);
	munmap((void *) lock, sizeof(*lock));
}

struct fio_rwlock *fio_rwlock_init(void)
{
	struct fio_rwlock *lock;
	pthread_rwlockattr_t attr;
	int ret;

	lock = (void *) mmap(NULL, sizeof(struct fio_rwlock),
				PROT_READ | PROT_WRITE,
				OS_MAP_ANON | MAP_SHARED, -1, 0);
	if (lock == MAP_FAILED) {
		perror("mmap rwlock");
		lock = NULL;
		goto err;
	}

	lock->magic = FIO_RWLOCK_MAGIC;

	ret = pthread_rwlockattr_init(&attr);
	if (ret) {
		log_err("pthread_rwlockattr_init: %s\n", strerror(ret));
		goto err;
	}
#ifdef FIO_HAVE_PSHARED_MUTEX
	ret = pthread_rwlockattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_rwlockattr_setpshared: %s\n", strerror(ret));
		goto destroy_attr;
	}

	ret = pthread_rwlock_init(&lock->lock, &attr);
#else
	ret = pthread_rwlock_init(&lock->lock, NULL);
#endif

	if (ret) {
		log_err("pthread_rwlock_init: %s\n", strerror(ret));
		goto destroy_attr;
	}

	pthread_rwlockattr_destroy(&attr);

	return lock;
destroy_attr:
	pthread_rwlockattr_destroy(&attr);
err:
	if (lock)
		fio_rwlock_remove(lock);
	return NULL;
}
