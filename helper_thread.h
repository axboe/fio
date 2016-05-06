#ifndef FIO_HELPER_THREAD_H
#define FIO_HELPER_THREAD_H

extern void helper_reset(void);
extern void helper_do_stat(void);
extern bool helper_should_exit(void);
extern void helper_thread_destroy(void);
extern void helper_thread_exit(void);
extern int helper_thread_create(struct fio_mutex *, struct sk_out *);

#endif
