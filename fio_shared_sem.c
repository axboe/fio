/*
 * Separate out the two helper functions for fio_sem from "fio_sem.c".
 * These two functions depend on fio shared memory. Other fio_sem
 * functions in "fio_sem.c" are used for fio shared memory. This file
 * separation is required to avoid build failures caused by circular
 * dependency.
 */

#include <stdio.h>

#include "fio_sem.h"
#include "smalloc.h"

/*
 * Allocate and initialize fio_sem lock object in the same manner as
 * fio_sem_init(), except the lock object is allocated from the fio
 * shared memory. This allows the parent process to free the lock
 * allocated by child processes.
 */
struct fio_sem *fio_shared_sem_init(int value)
{
	struct fio_sem *sem;

	sem = smalloc(sizeof(struct fio_sem));
	if (!sem)
		return NULL;

	if (!__fio_sem_init(sem, value))
		return sem;

	fio_shared_sem_remove(sem);
	return NULL;
}

/*
 * Free the fio_sem lock object allocated by fio_shared_sem_init().
 */
void fio_shared_sem_remove(struct fio_sem *sem)
{
	__fio_sem_remove(sem);
	sfree(sem);
}
