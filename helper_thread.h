#ifndef FIO_HELPER_THREAD_H
#define FIO_HELPER_THREAD_H

#include <stdbool.h>

struct fio_sem;
struct sk_out;

extern void helper_reset(void);
extern void helper_do_stat(void);
extern bool helper_should_exit(void);
extern void helper_thread_destroy(void);
extern void helper_thread_exit(void);
extern int helper_thread_create(struct fio_sem *, struct sk_out *);

#endif
