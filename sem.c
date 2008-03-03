#include <stdio.h>

#include "sem.h"
#include "smalloc.h"

void fio_sem_remove(struct fio_sem *sem)
{
	sfree(sem);
}

struct fio_sem *fio_sem_init(int value)
{
	struct fio_sem *sem;

	sem = smalloc(sizeof(*sem));
	if (!sem)
		return NULL;

	sem->sem_val = value;

	if (!sem_init(&sem->sem, 1, value))
		return sem;

	perror("sem_init");
	sfree(sem);
	return NULL;
}

void fio_sem_down(struct fio_sem *sem)
{
	sem_wait(&sem->sem);
}

void fio_sem_up(struct fio_sem *sem)
{
	sem_post(&sem->sem);
}
