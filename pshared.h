#ifndef FIO_PSHARED_H
#define FIO_PSHARED_H

#include <pthread.h>

extern int mutex_init_pshared(pthread_mutex_t *);
extern int cond_init_pshared(pthread_cond_t *);
extern int mutex_cond_init_pshared(pthread_mutex_t *, pthread_cond_t *);

#endif
