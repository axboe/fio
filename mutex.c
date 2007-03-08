#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/mman.h>

#include "mutex.h"

void fio_sem_remove(struct fio_sem *sem)
{
	unlink(sem->sem_name);
	munmap(sem, sizeof(*sem));
}

struct fio_sem *fio_sem_init(int value)
{
	struct fio_sem *sem = NULL;
	pthread_mutexattr_t attr;
	char sem_name[32];
	int fd;

	sprintf(sem_name, "/tmp/.fio_lock.XXXXXX");
	fd = mkstemp(sem_name);
	if (fd < 0) {
		perror("open sem");
		return NULL;
	}

	if (ftruncate(fd, sizeof(struct fio_sem)) < 0) {
		perror("ftruncate sem");
		goto err;
	}

	sem = mmap(NULL, sizeof(struct fio_sem), PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (sem == MAP_FAILED) {
		perror("mmap sem");
		close(fd);
		sem = NULL;
		goto err;
	}

	close(fd);
	sem->value = value;
	strcpy(sem->sem_name, sem_name);

	if (pthread_mutexattr_init(&attr)) {
		perror("pthread_mutexattr_init");
		goto err;
	}
	if (pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED)) {
		perror("pthread_mutexattr_setpshared");
		goto err;
	}
	if (pthread_mutex_init(&sem->lock, &attr)) {
		perror("pthread_mutex_init");
		goto err;
	}

	return sem;
err:
	if (sem)
		munmap(sem, sizeof(*sem));
	unlink(sem_name);
	return NULL;
}

void fio_sem_down(struct fio_sem *sem)
{
	pthread_mutex_lock(&sem->lock);
	while (sem->value == 0)
		pthread_cond_wait(&sem->cond, &sem->lock);
	sem->value--;
	pthread_mutex_unlock(&sem->lock);
}

void fio_sem_up(struct fio_sem *sem)
{
	pthread_mutex_lock(&sem->lock);
	if (!sem->value)
		pthread_cond_signal(&sem->cond);
	sem->value++;
	pthread_mutex_unlock(&sem->lock);
}
