#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>

#include "mutex.h"
#include "arch/arch.h"

void fio_mutex_remove(struct fio_mutex *mutex)
{
	close(mutex->mutex_fd);
	munmap(mutex, sizeof(*mutex));
}

struct fio_mutex *fio_mutex_init(int value)
{
	char mutex_name[] = "/tmp/.fio_mutex.XXXXXX";
	struct fio_mutex *mutex = NULL;
	pthread_mutexattr_t attr;
	pthread_condattr_t cond;
	int fd;

	fd = mkstemp(mutex_name);
	if (fd < 0) {
		perror("open mutex");
		return NULL;
	}

	if (ftruncate(fd, sizeof(struct fio_mutex)) < 0) {
		perror("ftruncate mutex");
		goto err;
	}

	mutex = mmap(NULL, sizeof(struct fio_mutex), PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (mutex == MAP_FAILED) {
		perror("mmap mutex");
		close(fd);
		mutex = NULL;
		goto err;
	}

	unlink(mutex_name);
	mutex->mutex_fd = fd;
	mutex->value = value;

	if (pthread_mutexattr_init(&attr)) {
		perror("pthread_mutexattr_init");
		goto err;
	}
	if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
		perror("pthread_mutexattr_setpshared");
		goto err;
	}

	pthread_condattr_init(&cond);
	pthread_condattr_setpshared(&cond, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(&mutex->cond, &cond);

	if (pthread_mutex_init(&mutex->lock, &attr)) {
		perror("pthread_mutex_init");
		goto err;
	}

	return mutex;
err:
	if (mutex)
		fio_mutex_remove(mutex);

	unlink(mutex_name);
	return NULL;
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
