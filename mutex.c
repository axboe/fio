#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/mman.h>

#include "fio.h"
#include "log.h"
#include "mutex.h"
#include "arch/arch.h"
#include "os/os.h"
#include "helpers.h"
#include "time.h"
#include "gettime.h"

void fio_mutex_remove(struct fio_mutex *mutex)
{
	pthread_cond_destroy(&mutex->cond);
	munmap((void *) mutex, sizeof(*mutex));
}

struct fio_mutex *fio_mutex_init(int value)
{
	struct fio_mutex *mutex = NULL;
	pthread_mutexattr_t attr;
	pthread_condattr_t cond;
	int ret;

	mutex = (void *) mmap(NULL, sizeof(struct fio_mutex),
				PROT_READ | PROT_WRITE,
				OS_MAP_ANON | MAP_SHARED, -1, 0);
	if (mutex == MAP_FAILED) {
		perror("mmap mutex");
		mutex = NULL;
		goto err;
	}

	mutex->value = value;

	ret = pthread_mutexattr_init(&attr);
	if (ret) {
		log_err("pthread_mutexattr_init: %s\n", strerror(ret));
		goto err;
	}

	/*
	 * Not all platforms support process shared mutexes (FreeBSD)
	 */
#ifdef FIO_HAVE_PSHARED_MUTEX
	ret = pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
	if (ret) {
		log_err("pthread_mutexattr_setpshared: %s\n", strerror(ret));
		goto err;
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
		goto err;
	}

	pthread_condattr_destroy(&cond);
	pthread_mutexattr_destroy(&attr);

	return mutex;
err:
	if (mutex)
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
		if (ret == ETIMEDOUT && !mutex_timed_out(&tv_s, seconds)) {
			pthread_mutex_lock(&mutex->lock);
			ret = 0;
		}

		mutex->waiters--;
	}

	if (!ret) {
		mutex->value--;
		pthread_mutex_unlock(&mutex->lock);
	}

	return ret;
}

void fio_mutex_down(struct fio_mutex *mutex)
{
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
	pthread_mutex_lock(&mutex->lock);
	read_barrier();
	if (!mutex->value && mutex->waiters)
		pthread_cond_signal(&mutex->cond);
	mutex->value++;
	pthread_mutex_unlock(&mutex->lock);
}

void fio_mutex_down_write(struct fio_mutex *mutex)
{
	pthread_mutex_lock(&mutex->lock);

	while (mutex->value != 0) {
		mutex->waiters++;
		pthread_cond_wait(&mutex->cond, &mutex->lock);
		mutex->waiters--;
	}

	mutex->value--;
	pthread_mutex_unlock(&mutex->lock);
}

void fio_mutex_down_read(struct fio_mutex *mutex)
{
	pthread_mutex_lock(&mutex->lock);

	while (mutex->value < 0) {
		mutex->waiters++;
		pthread_cond_wait(&mutex->cond, &mutex->lock);
		mutex->waiters--;
	}

	mutex->value++;
	pthread_mutex_unlock(&mutex->lock);
}

void fio_mutex_up_read(struct fio_mutex *mutex)
{
	pthread_mutex_lock(&mutex->lock);
	mutex->value--;
	read_barrier();
	if (mutex->value >= 0 && mutex->waiters)
		pthread_cond_signal(&mutex->cond);
	pthread_mutex_unlock(&mutex->lock);
}

void fio_mutex_up_write(struct fio_mutex *mutex)
{
	pthread_mutex_lock(&mutex->lock);
	mutex->value++;
	read_barrier();
	if (mutex->value >= 0 && mutex->waiters)
		pthread_cond_signal(&mutex->cond);
	pthread_mutex_unlock(&mutex->lock);
}
