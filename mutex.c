#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/mman.h>

#include "log.h"
#include "mutex.h"
#include "arch/arch.h"
#include "os/os.h"
#include "helpers.h"

void fio_mutex_remove(struct fio_mutex *mutex)
{
	close(mutex->mutex_fd);
	munmap((void *) mutex, sizeof(*mutex));
}

struct fio_mutex *fio_mutex_init(int value)
{
	char mutex_name[] = "/tmp/.fio_mutex.XXXXXX";
	struct fio_mutex *mutex = NULL;
	pthread_mutexattr_t attr;
	pthread_condattr_t cond;
	int fd, ret, mflag;

	fd = mkstemp(mutex_name);
	if (fd < 0) {
		perror("open mutex");
		return NULL;
	}

#ifdef FIO_HAVE_FALLOCATE
	ret = posix_fallocate(fd, 0, sizeof(struct fio_mutex));
	if (ret > 0) {
		fprintf(stderr, "posix_fallocate mutex failed: %s\n", strerror(ret));
		goto err;
	}
#endif

	if (ftruncate(fd, sizeof(struct fio_mutex)) < 0) {
		perror("ftruncate mutex");
		goto err;
	}

	mutex = (void *) mmap(NULL, sizeof(struct fio_mutex),
				PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (mutex == MAP_FAILED) {
		perror("mmap mutex");
		close(fd);
		mutex = NULL;
		goto err;
	}

	unlink(mutex_name);
	mutex->mutex_fd = fd;
	mutex->value = value;

	/*
	 * Not all platforms support process shared mutexes (FreeBSD)
	 */
#ifdef FIO_HAVE_PSHARED_MUTEX
	mflag = PTHREAD_PROCESS_SHARED;
#else
	mflag = PTHREAD_PROCESS_PRIVATE;
#endif

	ret = pthread_mutexattr_init(&attr);
	if (ret) {
		log_err("pthread_mutexattr_init: %s\n", strerror(ret));
		goto err;
	}
#ifdef FIO_HAVE_PSHARED_MUTEX
	ret = pthread_mutexattr_setpshared(&attr, mflag);
	if (ret) {
		log_err("pthread_mutexattr_setpshared: %s\n", strerror(ret));
		goto err;
	}
#endif

	pthread_condattr_init(&cond);
#ifdef FIO_HAVE_PSHARED_MUTEX
	pthread_condattr_setpshared(&cond, mflag);
#endif
	pthread_cond_init(&mutex->cond, &cond);

	ret = pthread_mutex_init(&mutex->lock, &attr);
	if (ret) {
		log_err("pthread_mutex_init: %s\n", strerror(ret));
		goto err;
	}

	return mutex;
err:
	if (mutex)
		fio_mutex_remove(mutex);

	unlink(mutex_name);
	return NULL;
}

int fio_mutex_down_timeout(struct fio_mutex *mutex, unsigned int seconds)
{
	struct timespec t;
	int ret = 0;

	clock_gettime(CLOCK_REALTIME, &t);
	t.tv_sec += seconds;

	pthread_mutex_lock(&mutex->lock);

	while (!mutex->value && !ret) {
		mutex->waiters++;
		ret = pthread_cond_timedwait(&mutex->cond, &mutex->lock, &t);
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
