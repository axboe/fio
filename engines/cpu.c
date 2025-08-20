/*
 * CPU engine
 *
 * Doesn't transfer any data, merely burns CPU cycles according to
 * the settings.
 *
 */
#include "../fio.h"
#include "../optgroup.h"

// number of 32 bit integers to sort
static size_t qsort_size = (256 * (1ULL << 10)); // 256KB

struct mwc {
	uint32_t w;
	uint32_t z;
};

enum stress_mode {
	FIO_CPU_NOOP = 0,
	FIO_CPU_QSORT = 1,
};

struct cpu_options {
	void *pad;
	unsigned int cpuload;
	unsigned int cpucycle;
	enum stress_mode cpumode;
	unsigned int exit_io_done;
	int32_t *qsort_data;
};

static struct fio_option options[] = {
	{
		.name	= "cpuload",
		.lname	= "CPU load",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct cpu_options, cpuload),
		.help	= "Use this percentage of CPU",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name     = "cpumode",
		.lname    = "cpumode",
		.type     = FIO_OPT_STR,
		.help     = "Stress mode",
		.off1     = offsetof(struct cpu_options, cpumode),
		.def      = "noop",
		.posval = {
			  { .ival = "noop",
			    .oval = FIO_CPU_NOOP,
			    .help = "NOOP instructions",
			  },
			  { .ival = "qsort",
			    .oval = FIO_CPU_QSORT,
			    .help = "QSORT computation",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_INVALID,
	},
	{
		.name	= "cpuchunks",
		.lname	= "CPU chunk",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct cpu_options, cpucycle),
		.help	= "Length of the CPU burn cycles (usecs)",
		.def	= "50000",
		.parent = "cpuload",
		.hide	= 1,
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= "exit_on_io_done",
		.lname	= "Exit when IO threads are done",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct cpu_options, exit_io_done),
		.help	= "Exit when IO threads finish",
		.def	= "0",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_INVALID,
	},
	{
		.name	= NULL,
	},
};

/*
 *  mwc32()
 *      Multiply-with-carry random numbers
 *      fast pseudo random number generator, see
 *      http://www.cse.yorku.ca/~oz/marsaglia-rng.html
 */
static uint32_t mwc32(struct mwc *mwc)
{
        mwc->z = 36969 * (mwc->z & 65535) + (mwc->z >> 16);
        mwc->w = 18000 * (mwc->w & 65535) + (mwc->w >> 16);
        return (mwc->z << 16) + mwc->w;
}

/*
 *  stress_qsort_cmp_1()
 *	qsort comparison - sort on int32 values
 */
static int stress_qsort_cmp_1(const void *p1, const void *p2)
{
	const int32_t *i1 = (const int32_t *)p1;
	const int32_t *i2 = (const int32_t *)p2;

	if (*i1 > *i2)
		return 1;
	else if (*i1 < *i2)
		return -1;
	else
		return 0;
}

/*
 *  stress_qsort_cmp_2()
 *	qsort comparison - reverse sort on int32 values
 */
static int stress_qsort_cmp_2(const void *p1, const void *p2)
{
	return stress_qsort_cmp_1(p2, p1);
}

/*
 *  stress_qsort_cmp_3()
 *	qsort comparison - sort on int8 values
 */
static int stress_qsort_cmp_3(const void *p1, const void *p2)
{
	const int8_t *i1 = (const int8_t *)p1;
	const int8_t *i2 = (const int8_t *)p2;

	/* Force re-ordering on 8 bit value */
	return *i1 - *i2;
}

static int do_qsort(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	struct cpu_options *co = td->eo;
	struct timespec start, now;

	fio_get_mono_time(&start);

	/* Sort "random" data */
	qsort(co->qsort_data, qsort_size, sizeof(*(co->qsort_data)), stress_qsort_cmp_1);

	/* Reverse sort */
	qsort(co->qsort_data, qsort_size, sizeof(*(co->qsort_data)), stress_qsort_cmp_2);

	/* And re-order by byte compare */
	qsort((uint8_t *)co->qsort_data, qsort_size * 4, sizeof(uint8_t), stress_qsort_cmp_3);

	/* Reverse sort this again */
	qsort(co->qsort_data, qsort_size, sizeof(*(co->qsort_data)), stress_qsort_cmp_2);
	fio_get_mono_time(&now);

	/* Adjusting cpucycle automatically to be as close as possible to the
	 * expected cpuload The time to execute do_qsort() may change over time
	 * as per : - the job concurrency - the cpu clock adjusted by the power
	 * management After every do_qsort() call, the next thinktime is
	 * adjusted regarding the last run performance
	 */
	co->cpucycle = utime_since(&start, &now);
	o->thinktime = ((unsigned long long) co->cpucycle *
				(100 - co->cpuload)) / co->cpuload;

	return 0;
}

static enum fio_q_status fio_cpuio_queue(struct thread_data *td,
					 struct io_u fio_unused *io_u)
{
	struct cpu_options *co = td->eo;

	if (co->exit_io_done && !fio_running_or_pending_io_threads()) {
		td->done = 1;
		return FIO_Q_BUSY;
	}

	switch (co->cpumode) {
	case FIO_CPU_NOOP:
		usec_spin(co->cpucycle);
		break;
	case FIO_CPU_QSORT:
		do_qsort(td);
		break;
	}

	return FIO_Q_COMPLETED;
}

static int noop_init(struct thread_data *td)
{
	struct cpu_options *co = td->eo;

	log_info("%s (noop): ioengine=%s, cpuload=%u, cpucycle=%u\n",
		td->o.name, td->io_ops->name, co->cpuload, co->cpucycle);
	return 0;
}

static int qsort_cleanup(struct thread_data *td)
{
	struct cpu_options *co = td->eo;

	if (co->qsort_data) {
		free(co->qsort_data);
		co->qsort_data = NULL;
	}

	return 0;
}

static int qsort_init(struct thread_data *td)
{
	/* Setting up a default entropy */
	struct mwc mwc = { 521288629UL, 362436069UL };
	struct cpu_options *co = td->eo;
	int32_t *ptr;
	int i;

	co->qsort_data = calloc(qsort_size, sizeof(*co->qsort_data));
	if (co->qsort_data == NULL) {
		td_verror(td, ENOMEM, "qsort_init");
		return 1;
	}

	/* This is expensive, init the memory once */
	for (ptr = co->qsort_data, i = 0; i < qsort_size; i++)
		*ptr++ = mwc32(&mwc);

	log_info("%s (qsort): ioengine=%s, cpuload=%u, cpucycle=%u\n",
		td->o.name, td->io_ops->name, co->cpuload, co->cpucycle);

	return 0;
}

static int fio_cpuio_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;
	struct cpu_options *co = td->eo;
	int td_previous_state;
	char *msg;

	if (!co->cpuload) {
		td_vmsg(td, EINVAL, "cpu thread needs rate (cpuload=)","cpuio");
		return 1;
	}

	if (co->cpuload > 100)
		co->cpuload = 100;

	/* Saving the current thread state */
	td_previous_state = td->runstate;

	/* Reporting that we are preparing the engine
	 * This is useful as the qsort() calibration takes time
	 * This prevents the job from starting before init is completed
	 */
	td_set_runstate(td, TD_SETTING_UP);

	/*
	 * set thinktime_sleep and thinktime_spin appropriately
	 */
	o->thinktime_blocks = 1;
	o->thinktime_blocks_type = THINKTIME_BLOCKS_TYPE_COMPLETE;
	o->thinktime_spin = 0;
	o->thinktime = ((unsigned long long) co->cpucycle *
				(100 - co->cpuload)) / co->cpuload;

	o->nr_files = o->open_files = 1;

	switch (co->cpumode) {
	case FIO_CPU_NOOP:
		noop_init(td);
		break;
	case FIO_CPU_QSORT:
		qsort_init(td);
		break;
	default:
		if (asprintf(&msg, "bad cpu engine mode: %d", co->cpumode) < 0)
			msg = NULL;
		td_vmsg(td, EINVAL, msg ? : "(?)", __func__);
		free(msg);
		return 1;
	}

	/* Let's restore the previous state. */
	td_set_runstate(td, td_previous_state);
	return 0;
}

static void fio_cpuio_cleanup(struct thread_data *td)
{
	struct cpu_options *co = td->eo;

	switch (co->cpumode) {
	case FIO_CPU_NOOP:
		break;
	case FIO_CPU_QSORT:
		qsort_cleanup(td);
		break;
	}
}

static int fio_cpuio_open(struct thread_data fio_unused *td,
			  struct fio_file fio_unused *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name			= "cpuio",
	.version		= FIO_IOOPS_VERSION,
	.queue			= fio_cpuio_queue,
	.init			= fio_cpuio_init,
	.cleanup		= fio_cpuio_cleanup,
	.open_file		= fio_cpuio_open,
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO | FIO_NOIO,
	.options		= options,
	.option_struct_size	= sizeof(struct cpu_options),
};

static void fio_init fio_cpuio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_cpuio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
