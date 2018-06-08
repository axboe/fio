#ifndef FIO_IDLETIME_H
#define FIO_IDLETIME_H

#include <sys/time.h>
#include <sys/types.h>
#include "os/os.h"

#define CALIBRATE_RUNS  10
#define CALIBRATE_SCALE 1000
#define MAX_CPU_STR_LEN 32

enum {
	IDLE_PROF_OPT_NONE,
	IDLE_PROF_OPT_CALI,                /* calibration only */
	IDLE_PROF_OPT_SYSTEM,
	IDLE_PROF_OPT_PERCPU
};

enum {
	 IDLE_PROF_STATUS_OK,
	 IDLE_PROF_STATUS_CALI_STOP,
	 IDLE_PROF_STATUS_PROF_STOP,
	 IDLE_PROF_STATUS_ABORT
};

struct idle_prof_thread {
	pthread_t thread;
	int cpu;
	int state;
	struct timespec tps;
	struct timespec tpe;
	double cali_time; /* microseconds to finish a unit work */
	double loops;
	double idleness;
	unsigned char *data;             /* bytes to be touched */
	pthread_cond_t  cond;
	pthread_mutex_t init_lock;
	pthread_mutex_t start_lock;

	os_cpu_mask_t cpu_mask;
};

struct idle_prof_common {
	struct idle_prof_thread *ipts;
	int nr_cpus;
	int status;
	int opt;
	double cali_mean;
	double cali_stddev;
	void *buf;    /* single data allocation for all threads */
};

extern int fio_idle_prof_parse_opt(const char *);

extern void fio_idle_prof_init(void);
extern void fio_idle_prof_start(void);
extern void fio_idle_prof_stop(void);

extern void show_idle_prof_stats(int, struct json_object *, struct buf_output *);

extern void fio_idle_prof_cleanup(void);

#endif
