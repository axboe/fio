#include "../fio.h"
#include "../profile.h"
#include "../parse.h"

#define OBJ_SIZE	1536		/* each object */
#define W_BUF_SIZE	128 * 1024	/* write coalescing */

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
		.max_usec =	5000,
		.max_perm =	10,
	},
	{
		.max_usec = 	64000,
		.max_perm =	1,
	},
};

struct act_prof_data {
	struct timeval sample_tv;
	uint64_t lat_buckets[ACT_MAX_CRIT];
	uint64_t total_ios;
};

static char *device_names;
static unsigned int load = 1;

static const char *act_opts[128] = {
	"direct=1",
	"ioengine=sync",
	"random_generator=lfsr",
	"runtime=24h",
	"time_based=1",
	NULL,
};
static unsigned int opt_idx = 5;
static unsigned int org_idx;

static void act_add_opt(const char *format, ...) __attribute__ ((__format__ (__printf__, 1, 2)));

static struct fio_option options[] = {
	{
		.name	= "device-names",
		.lname	= "device-names",
		.type	= FIO_OPT_STR_STORE,
		.roff1	= &device_names,
		.help	= "Devices to use",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= "load",
		.lname	= "Load multiplier",
		.type	= FIO_OPT_INT,
		.roff1	= &load,
		.help	= "ACT load multipler (default 1x)",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_ACT,
	},
	{
		.name	= NULL,
	},
};

static void act_add_opt(const char *str, ...)
{
	char buffer[512];
	va_list args;
	size_t len;

	va_start(args, str);
	len = vsnprintf(buffer, sizeof(buffer), str, args);
	va_end(args);

	if (len)
		act_opts[opt_idx++] = strdup(buffer);
}

static void act_add_dev(const char *dev)
{
	act_add_opt("name=act-read-%s", dev);
	act_add_opt("filename=%s", dev);
	act_add_opt("rw=randread");
	act_add_opt("rate_iops=%u", load * R_LOAD);

	act_add_opt("name=act-write-%s", dev);
	act_add_opt("filename=%s", dev);
	act_add_opt("rw=randwrite");
	act_add_opt("rate_iops=%u", load * W_LOAD);
}

/*
 * Fill our private options into the command line
 */
static int act_prep_cmdline(void)
{
	if (!device_names) {
		log_err("act: need device-names\n");
		return 1;
	}

	org_idx = opt_idx;
	act_add_opt("bs=%u", OBJ_SIZE);

	do {
		char *dev;

		dev = strsep(&device_names, ",");
		if (!dev)
			break;

		act_add_dev(dev);
	} while (1);

	return 0;
}

static int act_io_u_lat(struct thread_data *td, uint64_t usec)
{
	struct act_prof_data *apd = td->prof_data;
	int i, ret = 0;
	double perm;

	apd->total_ios++;

	for (i = 0; i < ACT_MAX_CRIT; i++) {
		if (usec <= act_pass[i].max_usec) {
			apd->lat_buckets[i]++;
			break;
		}
	}

	if (i == ACT_MAX_CRIT) {
		log_err("act: max latency exceeded!\n");
		return 1;
	}

	if (time_since_now(&apd->sample_tv) < SAMPLE_SEC)
		return 0;

	/* SAMPLE_SEC has passed, check criteria for pass */
	for (i = 0; i < ACT_MAX_CRIT; i++) {
		perm = (1000.0 * apd->lat_buckets[i]) / apd->total_ios;
		if (perm <= act_pass[i].max_perm)
			continue;

		log_err("act: %f%% exceeds pass criteria of %f%%\n", perm / 10.0, (double) act_pass[i].max_perm / 10.0);
		ret = 1;
		break;
	}

	fio_gettime(&apd->sample_tv, NULL);
	return ret;
}

static int act_td_init(struct thread_data *td)
{
	struct act_prof_data *apd;

	apd = calloc(sizeof(*apd), 1);
	fio_gettime(&apd->sample_tv, NULL);
	td->prof_data = apd;
	return 0;
}

static void act_td_exit(struct thread_data *td)
{
	free(td->prof_data);
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
	.prep_cmd	= act_prep_cmdline,
	.cmdline	= act_opts,
	.io_ops		= &act_io_ops,
};

static void fio_init act_register(void)
{
	if (register_profile(&act_profile))
		log_err("fio: failed to register profile 'act'\n");
}

static void fio_exit act_unregister(void)
{
	while (org_idx && org_idx < opt_idx)
		free((void *) act_opts[++org_idx]);

	unregister_profile(&act_profile);
}
