#ifndef FIO_SEM_H
#define FIO_SEM_H

#include <semaphore.h>

struct fio_sem {
	sem_t sem;
	int sem_val;
};

extern struct fio_sem *fio_sem_init(int);
extern void fio_sem_remove(struct fio_sem *);
extern void fio_sem_down(struct fio_sem *);
extern void fio_sem_up(struct fio_sem *);

#endif
