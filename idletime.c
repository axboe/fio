#include <math.h>
#include "fio.h"
#include "json.h"
#include "idletime.h"

static volatile struct idle_prof_common ipc;

/*
 * Get time to complete an unit work on a particular cpu.
 * The minimum number in CALIBRATE_RUNS runs is returned.
 */
static double calibrate_unit(unsigned char *data)
{
	unsigned long t, i, j, k;
	struct timespec tps;
	double tunit = 0.0;

	for (i = 0; i < CALIBRATE_RUNS; i++) {

		fio_gettime(&tps, NULL);
		/* scale for less variance */
		for (j = 0; j < CALIBRATE_SCALE; j++) {
			/* unit of work */
			for (k=0; k < page_size; k++) {
				data[(k + j) % page_size] = k % 256;
				/*
				 * we won't see STOP here. this is to match
				 * the same statement in the profiling loop.
				 */
				if (ipc.status == IDLE_PROF_STATUS_PROF_STOP)
					return 0.0;
			}
		}

		t = utime_since_now(&tps);
		if (!t)
			continue;

		/* get the minimum time to complete CALIBRATE_SCALE units */
		if ((i == 0) || ((double)t < tunit))
			tunit = (double)t;
	}

	return tunit / CALIBRATE_SCALE;
}

static void free_cpu_affinity(struct idle_prof_thread *ipt)
{
#if defined(FIO_HAVE_CPU_AFFINITY)
	fio_cpuset_exit(&ipt->cpu_mask);
#endif
}

static int set_cpu_affinity(struct idle_prof_thread *ipt)
{
#if defined(FIO_HAVE_CPU_AFFINITY)
	if (fio_cpuset_init(&ipt->cpu_mask)) {
		log_err("fio: cpuset init failed\n");
		return -1;
	}

	fio_cpu_set(&ipt->cpu_mask, ipt->cpu);

	if (fio_setaffinity(gettid(), ipt->cpu_mask)) {
		log_err("fio: fio_setaffinity failed\n");
		fio_cpuset_exit(&ipt->cpu_mask);
		return -1;
	}

	return 0;
#else
	log_err("fio: fio_setaffinity not supported\n");
	return -1;
#endif
}

static void *idle_prof_thread_fn(void *data)
{
	int retval;
	unsigned long j, k;
	struct idle_prof_thread *ipt = data;

	/* wait for all threads are spawned */
	pthread_mutex_lock(&ipt->init_lock);

	/* exit if any other thread failed to start */
	if (ipc.status == IDLE_PROF_STATUS_ABORT) {
		pthread_mutex_unlock(&ipt->init_lock);
		return NULL;
	}

	retval = set_cpu_affinity(ipt);
	if (retval == -1) {
		ipt->state = TD_EXITED;
		pthread_mutex_unlock(&ipt->init_lock);
		return NULL;
        }

	ipt->cali_time = calibrate_unit(ipt->data);

	/* delay to set IDLE class till now for better calibration accuracy */
#if defined(CONFIG_SCHED_IDLE)
	if ((retval = fio_set_sched_idle()))
		log_err("fio: fio_set_sched_idle failed\n");
#else
	retval = -1;
	log_err("fio: fio_set_sched_idle not supported\n");
#endif
	if (retval == -1) {
		ipt->state = TD_EXITED;
		pthread_mutex_unlock(&ipt->init_lock);
		goto do_exit;
	}

	ipt->state = TD_INITIALIZED;

	/* signal the main thread that calibration is done */
	pthread_cond_signal(&ipt->cond);
	pthread_mutex_unlock(&ipt->init_lock);

	/* wait for other calibration to finish */
	pthread_mutex_lock(&ipt->start_lock);

	/* exit if other threads failed to initialize */
	if (ipc.status == IDLE_PROF_STATUS_ABORT) {
		pthread_mutex_unlock(&ipt->start_lock);
		goto do_exit;
	}

	/* exit if we are doing calibration only */
	if (ipc.status == IDLE_PROF_STATUS_CALI_STOP) {
		pthread_mutex_unlock(&ipt->start_lock);
		goto do_exit;
	}

	fio_gettime(&ipt->tps, NULL);
	ipt->state = TD_RUNNING;

	j = 0;
	while (1) {
		for (k = 0; k < page_size; k++) {
			ipt->data[(k + j) % page_size] = k % 256;
			if (ipc.status == IDLE_PROF_STATUS_PROF_STOP) {
				fio_gettime(&ipt->tpe, NULL);
				goto idle_prof_done;
			}
		}
		j++;
	}

idle_prof_done:

	ipt->loops = j + (double) k / page_size;
	ipt->state = TD_EXITED;
	pthread_mutex_unlock(&ipt->start_lock);

do_exit:
	free_cpu_affinity(ipt);
	return NULL;
}

/* calculate mean and standard deviation to complete an unit of work */
static void calibration_stats(void)
{
	int i;
	double sum = 0.0, var = 0.0;
	struct idle_prof_thread *ipt;

	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		sum += ipt->cali_time;
	}

	ipc.cali_mean = sum/ipc.nr_cpus;

	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		var += pow(ipt->cali_time-ipc.cali_mean, 2);
	}

	ipc.cali_stddev = sqrt(var/(ipc.nr_cpus-1));
}

void fio_idle_prof_init(void)
{
	int i, ret;
	struct timespec ts;
	pthread_attr_t tattr;
	pthread_condattr_t cattr;
	struct idle_prof_thread *ipt;

	ipc.nr_cpus = cpus_online();
	ipc.status = IDLE_PROF_STATUS_OK;

	if (ipc.opt == IDLE_PROF_OPT_NONE)
		return;

	ret = pthread_condattr_init(&cattr);
	assert(ret == 0);
#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
	ret = pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC);
	assert(ret == 0);
#endif

	if ((ret = pthread_attr_init(&tattr))) {
		log_err("fio: pthread_attr_init %s\n", strerror(ret));
		return;
	}
	if ((ret = pthread_attr_setscope(&tattr, PTHREAD_SCOPE_SYSTEM))) {
		log_err("fio: pthread_attr_setscope %s\n", strerror(ret));
		return;
	}

	ipc.ipts = malloc(ipc.nr_cpus * sizeof(struct idle_prof_thread));
	if (!ipc.ipts) {
		log_err("fio: malloc failed\n");
		return;
	}

	ipc.buf = malloc(ipc.nr_cpus * page_size);
	if (!ipc.buf) {
		log_err("fio: malloc failed\n");
		free(ipc.ipts);
		return;
	}

	/*
	 * profiling aborts on any single thread failure since the
	 * result won't be accurate if any cpu is not used.
	 */
	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];

		ipt->cpu = i;	
		ipt->state = TD_NOT_CREATED;
		ipt->data = (unsigned char *)(ipc.buf + page_size * i);

		if ((ret = pthread_mutex_init(&ipt->init_lock, NULL))) {
			ipc.status = IDLE_PROF_STATUS_ABORT;
			log_err("fio: pthread_mutex_init %s\n", strerror(ret));
			break;
		}

		if ((ret = pthread_mutex_init(&ipt->start_lock, NULL))) {
			ipc.status = IDLE_PROF_STATUS_ABORT;
			log_err("fio: pthread_mutex_init %s\n", strerror(ret));
			break;
		}

		if ((ret = pthread_cond_init(&ipt->cond, &cattr))) {
			ipc.status = IDLE_PROF_STATUS_ABORT;
			log_err("fio: pthread_cond_init %s\n", strerror(ret));
			break;
		}

		/* make sure all threads are spawned before they start */
		pthread_mutex_lock(&ipt->init_lock);

		/* make sure all threads finish init before profiling starts */
		pthread_mutex_lock(&ipt->start_lock);

		if ((ret = pthread_create(&ipt->thread, &tattr, idle_prof_thread_fn, ipt))) {
			ipc.status = IDLE_PROF_STATUS_ABORT;
			log_err("fio: pthread_create %s\n", strerror(ret));
			break;
		} else
			ipt->state = TD_CREATED;

		if ((ret = pthread_detach(ipt->thread))) {
			/* log error and let the thread spin */
			log_err("fio: pthread_detach %s\n", strerror(ret));
		}
	}

	/*
	 * let good threads continue so that they can exit
	 * if errors on other threads occurred previously.
	 */
	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		pthread_mutex_unlock(&ipt->init_lock);
	}
	
	if (ipc.status == IDLE_PROF_STATUS_ABORT)
		return;
	
	/* wait for calibration to finish */
	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		pthread_mutex_lock(&ipt->init_lock);
		while ((ipt->state != TD_EXITED) &&
		       (ipt->state!=TD_INITIALIZED)) {
#ifdef CONFIG_PTHREAD_CONDATTR_SETCLOCK
			clock_gettime(CLOCK_MONOTONIC, &ts);
#else
			clock_gettime(CLOCK_REALTIME, &ts);
#endif
			ts.tv_sec += 1;
			pthread_cond_timedwait(&ipt->cond, &ipt->init_lock, &ts);
		}
		pthread_mutex_unlock(&ipt->init_lock);
	
		/*
		 * any thread failed to initialize would abort other threads
		 * later after fio_idle_prof_start. 
		 */	
		if (ipt->state == TD_EXITED)
			ipc.status = IDLE_PROF_STATUS_ABORT;
	}

	if (ipc.status != IDLE_PROF_STATUS_ABORT)
		calibration_stats();
	else
		ipc.cali_mean = ipc.cali_stddev = 0.0;

	if (ipc.opt == IDLE_PROF_OPT_CALI)
		ipc.status = IDLE_PROF_STATUS_CALI_STOP;
}

void fio_idle_prof_start(void)
{
	int i;
	struct idle_prof_thread *ipt;

	if (ipc.opt == IDLE_PROF_OPT_NONE)
		return;

	/* unlock regardless abort is set or not */
	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		pthread_mutex_unlock(&ipt->start_lock);
	}
}

void fio_idle_prof_stop(void)
{
	int i;
	uint64_t runt;
	struct timespec ts;
	struct idle_prof_thread *ipt;

	if (ipc.opt == IDLE_PROF_OPT_NONE)
		return;

	if (ipc.opt == IDLE_PROF_OPT_CALI)
		return;

	ipc.status = IDLE_PROF_STATUS_PROF_STOP;

	/* wait for all threads to exit from profiling */
	for (i = 0; i < ipc.nr_cpus; i++) {
		ipt = &ipc.ipts[i];
		pthread_mutex_lock(&ipt->start_lock);
		while ((ipt->state != TD_EXITED) &&
		       (ipt->state!=TD_NOT_CREATED)) {
			fio_gettime(&ts, NULL);
			ts.tv_sec += 1;
			/* timed wait in case a signal is not received */
			pthread_cond_timedwait(&ipt->cond, &ipt->start_lock, &ts);
		}
		pthread_mutex_unlock(&ipt->start_lock);

		/* calculate idleness */
		if (ipc.cali_mean != 0.0) {
			runt = utime_since(&ipt->tps, &ipt->tpe);
			if (runt)
				ipt->idleness = ipt->loops * ipc.cali_mean / runt;
			else
				ipt->idleness = 0.0;
		} else
			ipt->idleness = 0.0;
	}

	/*
	 * memory allocations are freed via explicit fio_idle_prof_cleanup
	 * after profiling stats are collected by apps.  
	 */
}

/*
 * return system idle percentage when cpu is -1;
 * return one cpu idle percentage otherwise.
 */
static double fio_idle_prof_cpu_stat(int cpu)
{
	int i, nr_cpus = ipc.nr_cpus;
	struct idle_prof_thread *ipt;
	double p = 0.0;

	if (ipc.opt == IDLE_PROF_OPT_NONE)
		return 0.0;

	if ((cpu >= nr_cpus) || (cpu < -1)) {
		log_err("fio: idle profiling invalid cpu index\n");
		return 0.0;
	}

	if (cpu == -1) {
		for (i = 0; i < nr_cpus; i++) {
			ipt = &ipc.ipts[i];
			p += ipt->idleness;
		}
		p /= nr_cpus;
	} else {
		ipt = &ipc.ipts[cpu];
		p = ipt->idleness;
	}

	return p * 100.0;
}

void fio_idle_prof_cleanup(void)
{
	if (ipc.ipts) {
		free(ipc.ipts);
		ipc.ipts = NULL;
	}

	if (ipc.buf) {
		free(ipc.buf);
		ipc.buf = NULL;
	}
}

int fio_idle_prof_parse_opt(const char *args)
{
	ipc.opt = IDLE_PROF_OPT_NONE; /* default */

	if (!args) {
		log_err("fio: empty idle-prof option string\n");
		return -1;
	}	

#if defined(FIO_HAVE_CPU_AFFINITY) && defined(CONFIG_SCHED_IDLE)
	if (strcmp("calibrate", args) == 0) {
		ipc.opt = IDLE_PROF_OPT_CALI;
		fio_idle_prof_init();
		fio_idle_prof_start();
		fio_idle_prof_stop();
		show_idle_prof_stats(FIO_OUTPUT_NORMAL, NULL, NULL);
		return 1;
	} else if (strcmp("system", args) == 0) {
		ipc.opt = IDLE_PROF_OPT_SYSTEM;
		return 0;
	} else if (strcmp("percpu", args) == 0) {
		ipc.opt = IDLE_PROF_OPT_PERCPU;
		return 0;
	} else {
		log_err("fio: incorrect idle-prof option: %s\n", args);
		return -1;
	}	
#else
	log_err("fio: idle-prof not supported on this platform\n");
	return -1;
#endif
}

void show_idle_prof_stats(int output, struct json_object *parent,
			  struct buf_output *out)
{
	int i, nr_cpus = ipc.nr_cpus;
	struct json_object *tmp;
	char s[MAX_CPU_STR_LEN];

	if (output == FIO_OUTPUT_NORMAL) {
		if (ipc.opt > IDLE_PROF_OPT_CALI)
			log_buf(out, "\nCPU idleness:\n");
		else if (ipc.opt == IDLE_PROF_OPT_CALI)
			log_buf(out, "CPU idleness:\n");

		if (ipc.opt >= IDLE_PROF_OPT_SYSTEM)
			log_buf(out, "  system: %3.2f%%\n", fio_idle_prof_cpu_stat(-1));

		if (ipc.opt == IDLE_PROF_OPT_PERCPU) {
			log_buf(out, "  percpu: %3.2f%%", fio_idle_prof_cpu_stat(0));
			for (i = 1; i < nr_cpus; i++)
				log_buf(out, ", %3.2f%%", fio_idle_prof_cpu_stat(i));
			log_buf(out, "\n");
		}

		if (ipc.opt >= IDLE_PROF_OPT_CALI) {
			log_buf(out, "  unit work: mean=%3.2fus,", ipc.cali_mean);
			log_buf(out, " stddev=%3.2f\n", ipc.cali_stddev);
		}

		return;
	}

	if ((ipc.opt != IDLE_PROF_OPT_NONE) && (output & FIO_OUTPUT_JSON)) {
		if (!parent)
			return;

		tmp = json_create_object();
		if (!tmp)
			return;

		json_object_add_value_object(parent, "cpu_idleness", tmp);
		json_object_add_value_float(tmp, "system", fio_idle_prof_cpu_stat(-1));

		if (ipc.opt == IDLE_PROF_OPT_PERCPU) {
			for (i = 0; i < nr_cpus; i++) {
				snprintf(s, MAX_CPU_STR_LEN, "cpu-%d", i);
				json_object_add_value_float(tmp, s, fio_idle_prof_cpu_stat(i));
			}
		}

		json_object_add_value_float(tmp, "unit_mean", ipc.cali_mean);
		json_object_add_value_float(tmp, "unit_stddev", ipc.cali_stddev);
	}
}
