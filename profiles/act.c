#include "../fio.h"
#include "../profile.h"
#include "../parse.h"
#include "../optgroup.h"

/*
 * 1x loads
 */
#define R_LOAD		2000
#define W_LOAD		1000

#define SAMPLE_SEC	3600		/* 1h checks */

struct act_pass_criteria {
	unsigned int max_usec;
	unsigned int max_perm;
};
#define ACT_MAX_CRIT	3

static struct act_pass_criteria act_pass[ACT_MAX_CRIT] = {
	{
		.max_usec =	1000,
		.max_perm =	50,
	},
	{
		.max_usec =	8000,
		.max_perm =	10,
	},
	{
		.max_usec = 	64000,
		.max_perm =	1,
	},
};

struct act_slice {
	uint64_t lat_buckets[ACT_MAX_CRIT];
	uint64_t total_ios;
};

struct act_run_data {
	struct fio_sem *sem;
	unsigned int pending;

	struct act_slice *slices;
	unsigned int nr_slices;
};
static struct act_run_data *act_run_data;

struct act_prof_data {
	struct timespec sample_tv;
	struct act_slice *slices;
	unsigned int cur_slice;
	unsigned int nr_slices;
};

#define ACT_MAX_OPTS	128
static const char *act_opts[ACT_MAX_OPTS] = {
	"direct=1",
	"ioengine=sync",
	"random_generator=lfsr",
	"group_reporting=1",
	"thread",
	NULL,
};
static unsigned int opt_idx = 5;
static unsigned int org_idx;

static int act_add_opt(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));

struct act_options {
	unsigned int pad;
	char *device_names;
	unsigned int load;
	unsigned int prep;
	unsigned int threads_per_queue;
	unsigned int num_read_blocks;
	unsigned int write_size;
	unsigned long long test_duration;
};

static struct act_options act_options;

static struct fio_option options[] = {
	{
		.name	= "device-names",
		.lname	= "device-names",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct act_options, device_names),
		.help	= "Devices to use",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
		.no_free = true,
	},
	{
		.name	= "load",
		.lname	= "Load multiplier",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct act_options, load),
		.help	= "ACT load multipler (default 1x)",
		.def	= "1",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "test-duration",
		.lname	= "Test duration",
		.type	= FIO_OPT_STR_VAL_TIME,
		.off1	= offsetof(struct act_options, test_duration),
		.help	= "How long the entire test takes to run",
		.def	= "24h",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "threads-per-queue",
		.lname	= "Number of read IO threads per device",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct act_options, threads_per_queue),
		.help	= "Number of read IO threads per device",
		.def	= "8",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "read-req-num-512-blocks",
		.lname	= "Number of 512B blocks to read",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct act_options, num_read_blocks),
		.help	= "Number of 512B blocks to read at the time",
		.def	= "3",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "large-block-op-kbytes",
		.lname	= "Size of large block ops in KiB (writes)",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct act_options, write_size),
		.help	= "Size of large block ops in KiB (writes)",
		.def	= "131072",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "prep",
		.lname	= "Run ACT prep phase",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct act_options, prep),
		.help	= "Set to run ACT prep phase",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= NULL,
	},
};

static int act_add_opt(const char *str, ...)
{
	char buffer[512];
	va_list args;
	size_t len;

	if (opt_idx == ACT_MAX_OPTS) {
		log_err("act: ACT_MAX_OPTS is too small\n");
		return 1;
	}

	va_start(args, str);
	len = vsnprintf(buffer, sizeof(buffer), str, args);
	va_end(args);

	if (len)
		act_opts[opt_idx++] = strdup(buffer);

	return 0;
}

static int act_add_rw(const char *dev, int reads)
{
	struct act_options *ao = &act_options;

	if (act_add_opt("name=act-%s-%s", reads ? "read" : "write", dev))
		return 1;
	if (act_add_opt("filename=%s", dev))
		return 1;
	if (act_add_opt("rw=%s", reads ? "randread" : "randwrite"))
		return 1;
	if (reads) {
		int rload = ao->load * R_LOAD / ao->threads_per_queue;

		if (act_add_opt("numjobs=%u", ao->threads_per_queue))
			return 1;
		if (act_add_opt("rate_iops=%u", rload))
			return 1;
		if (act_add_opt("bs=%u", ao->num_read_blocks * 512))
			return 1;
	} else {
		const int rsize = ao->write_size / (ao->num_read_blocks * 512);
		int wload = (ao->load * W_LOAD + rsize - 1) / rsize;

		if (act_add_opt("rate_iops=%u", wload))
			return 1;
		if (act_add_opt("bs=%u", ao->write_size))
			return 1;
	}

	return 0;
}

static int act_add_dev_prep(const char *dev)
{
	/* Add sequential zero phase */
	if (act_add_opt("name=act-prep-zeroes-%s", dev))
		return 1;
	if (act_add_opt("filename=%s", dev))
		return 1;
	if (act_add_opt("bs=1048576"))
		return 1;
	if (act_add_opt("zero_buffers"))
		return 1;
	if (act_add_opt("rw=write"))
		return 1;

	/* Randomly overwrite device */
	if (act_add_opt("name=act-prep-salt-%s", dev))
		return 1;
	if (act_add_opt("stonewall"))
		return 1;
	if (act_add_opt("filename=%s", dev))
		return 1;
	if (act_add_opt("bs=4096"))
		return 1;
	if (act_add_opt("ioengine=libaio"))
		return 1;
	if (act_add_opt("iodepth=64"))
		return 1;
	if (act_add_opt("rw=randwrite"))
		return 1;

	return 0;
}

static int act_add_dev(const char *dev)
{
	if (act_options.prep)
		return act_add_dev_prep(dev);

	if (act_add_opt("runtime=%llus", act_options.test_duration))
		return 1;
	if (act_add_opt("time_based=1"))
		return 1;

	if (act_add_rw(dev, 1))
		return 1;
	if (act_add_rw(dev, 0))
		return 1;

	return 0;
}

/*
 * Fill our private options into the command line
 */
static int act_prep_cmdline(void)
{
	if (!act_options.device_names) {
		log_err("act: you need to set IO target(s) with the "
			"device-names option.\n");
		return 1;
	}

	org_idx = opt_idx;

	do {
		char *dev;

		dev = strsep(&act_options.device_names, ",");
		if (!dev)
			break;

		if (act_add_dev(dev)) {
			log_err("act: failed adding device to the mix\n");
			break;
		}
	} while (1);

	return 0;
}

static int act_io_u_lat(struct thread_data *td, uint64_t nsec)
{
	struct act_prof_data *apd = td->prof_data;
	struct act_slice *slice;
	uint64_t usec = nsec / 1000ULL;
	int i, ret = 0;
	double perm;

	if (act_options.prep)
		return 0;

	/*
	 * Really should not happen, but lets not let jitter at the end
	 * ruin our day.
	 */
	if (apd->cur_slice >= apd->nr_slices)
		return 0;

	slice = &apd->slices[apd->cur_slice];
	slice->total_ios++;

	for (i = ACT_MAX_CRIT - 1; i >= 0; i--) {
		if (usec > act_pass[i].max_usec) {
			slice->lat_buckets[i]++;
			break;
		}
	}

	if (time_since_now(&apd->sample_tv) < SAMPLE_SEC)
		return 0;

	/* SAMPLE_SEC has passed, check criteria for pass */
	for (i = 0; i < ACT_MAX_CRIT; i++) {
		perm = (1000.0 * slice->lat_buckets[i]) / slice->total_ios;
		if (perm < act_pass[i].max_perm)
			continue;

		log_err("act: %f%% exceeds pass criteria of %f%%\n", perm / 10.0, (double) act_pass[i].max_perm / 10.0);
		ret = 1;
		break;
	}

	fio_gettime(&apd->sample_tv, NULL);
	apd->cur_slice++;
	return ret;
}

static void get_act_ref(void)
{
	fio_sem_down(act_run_data->sem);
	act_run_data->pending++;
	fio_sem_up(act_run_data->sem);
}

static int show_slice(struct act_slice *slice, unsigned int slice_num)
{
	unsigned int i, failed = 0;

	log_info("   %2u", slice_num);

	for (i = 0; i < ACT_MAX_CRIT; i++) {
		double perc = 0.0;

		if (slice->total_ios)
			perc = 100.0 * (double) slice->lat_buckets[i] / (double) slice->total_ios;
		if ((perc * 10.0) >= act_pass[i].max_perm)
			failed++;
		log_info("\t%2.2f", perc);
	}
	for (i = 0; i < ACT_MAX_CRIT; i++) {
		double perc = 0.0;

		if (slice->total_ios)
			perc = 100.0 * (double) slice->lat_buckets[i] / (double) slice->total_ios;
		log_info("\t%2.2f", perc);
	}
	log_info("\n");

	return failed;
}

static void act_show_all_stats(void)
{
	unsigned int i, fails = 0;

	log_info("        trans                   device\n");
	log_info("        %%>(ms)                  %%>(ms)\n");
	log_info(" slice");

	for (i = 0; i < ACT_MAX_CRIT; i++)
		log_info("\t %2u", act_pass[i].max_usec / 1000);
	for (i = 0; i < ACT_MAX_CRIT; i++)
		log_info("\t %2u", act_pass[i].max_usec / 1000);

	log_info("\n");
	log_info(" -----  -----   -----  ------   -----   -----  ------\n");

	for (i = 0; i < act_run_data->nr_slices; i++)
		fails += show_slice(&act_run_data->slices[i], i + 1);

	log_info("\nact: test complete, device(s): %s\n", fails ? "FAILED" : "PASSED");
}

static void put_act_ref(struct thread_data *td)
{
	struct act_prof_data *apd = td->prof_data;
	unsigned int i, slice;

	fio_sem_down(act_run_data->sem);

	if (!act_run_data->slices) {
		act_run_data->slices = calloc(apd->nr_slices, sizeof(struct act_slice));
		act_run_data->nr_slices = apd->nr_slices;
	}

	for (slice = 0; slice < apd->nr_slices; slice++) {
		struct act_slice *dst = &act_run_data->slices[slice];
		struct act_slice *src = &apd->slices[slice];

		dst->total_ios += src->total_ios;

		for (i = 0; i < ACT_MAX_CRIT; i++)
			dst->lat_buckets[i] += src->lat_buckets[i];
	}

	if (!--act_run_data->pending)
		act_show_all_stats();

	fio_sem_up(act_run_data->sem);
}

static int act_td_init(struct thread_data *td)
{
	struct act_prof_data *apd;
	unsigned int nr_slices;

	get_act_ref();

	apd = calloc(1, sizeof(*apd));
	nr_slices = (act_options.test_duration + SAMPLE_SEC - 1) / SAMPLE_SEC;
	apd->slices = calloc(nr_slices, sizeof(struct act_slice));
	apd->nr_slices = nr_slices;
	fio_gettime(&apd->sample_tv, NULL);
	td->prof_data = apd;
	return 0;
}

static void act_td_exit(struct thread_data *td)
{
	struct act_prof_data *apd = td->prof_data;

	put_act_ref(td);
	free(apd->slices);
	free(apd);
	td->prof_data = NULL;
}

static struct prof_io_ops act_io_ops = {
	.td_init	= act_td_init,
	.td_exit	= act_td_exit,
	.io_u_lat	= act_io_u_lat,
};

static struct profile_ops act_profile = {
	.name		= "act",
	.desc		= "ACT Aerospike like benchmark",
	.options	= options,
	.opt_data	= &act_options,
	.prep_cmd	= act_prep_cmdline,
	.cmdline	= act_opts,
	.io_ops		= &act_io_ops,
};

static void fio_init act_register(void)
{
	act_run_data = calloc(1, sizeof(*act_run_data));
	act_run_data->sem = fio_sem_init(FIO_SEM_UNLOCKED);

	if (register_profile(&act_profile))
		log_err("fio: failed to register profile 'act'\n");
}

static void fio_exit act_unregister(void)
{
	while (org_idx && org_idx < opt_idx)
		free((void *) act_opts[++org_idx]);

	unregister_profile(&act_profile);
	fio_sem_remove(act_run_data->sem);
	free(act_run_data->slices);
	free(act_run_data);
	act_run_data = NULL;
}
