#ifndef FIO_TP_H
#define FIO_TP_H

#include "../flist.h"

struct tp_work;
typedef int (tp_work_fn)(struct tp_work *);

struct tp_work {
	struct flist_head list;
	tp_work_fn *fn;
	int wait;
	int prio;
	pthread_cond_t cv;
	pthread_mutex_t lock;
	volatile int done;
};

struct tp_data {
	pthread_t thread;
	pthread_cond_t cv;
	pthread_mutex_t lock;
	struct flist_head work;
	volatile int thread_exit;
	pthread_cond_t sleep_cv;
	volatile int sleeping;
};

extern void tp_init(struct tp_data **);
extern void tp_exit(struct tp_data **);
extern void tp_queue_work(struct tp_data *, struct tp_work *);

#endif
