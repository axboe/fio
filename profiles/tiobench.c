#include "../fio.h"
#include "../profile.h"
#include "../parse.h"

static unsigned long long size;
static unsigned int loops = 1;
static unsigned int bs = 4096;
static unsigned int nthreads = 1;
static char *dir;

static char sz_idx[80], bs_idx[80], loop_idx[80], dir_idx[80], t_idx[80];

static const char *tb_opts[] = {
	"buffered=0", sz_idx, bs_idx, loop_idx, dir_idx, t_idx,
	"timeout=600", "group_reporting", "thread", "overwrite=1",
	"filename=.fio.tio.1:.fio.tio.2:.fio.tio.3:.fio.tio.4",
	"ioengine=sync",
	"name=seqwrite", "rw=write", "end_fsync=1",
	"name=randwrite", "stonewall", "rw=randwrite", "end_fsync=1",
	"name=seqread", "stonewall", "rw=read",
	"name=randread", "stonewall", "rw=randread", NULL,
};

struct tiobench_options {
	unsigned int pad;
	unsigned long long size;
	unsigned int loops;
	unsigned int bs;
	unsigned int nthreads;
	char *dir;
};

static struct tiobench_options tiobench_options;

static struct fio_option options[] = {
	{
		.name	= "size",
		.lname	= "Tiobench size",
		.type	= FIO_OPT_STR_VAL,
		.off1	= offsetof(struct tiobench_options, size),
		.help	= "Size in MB",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= "block",
		.lname	= "Tiobench block",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct tiobench_options, bs),
		.help	= "Block size in bytes",
		.def	= "4k",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= "numruns",
		.lname	= "Tiobench numruns",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct tiobench_options, loops),
		.help	= "Number of runs",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= "dir",
		.lname	= "Tiobench directory",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct tiobench_options, dir),
		.help	= "Test directory",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= "threads",
		.lname	= "Tiobench threads",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct tiobench_options, nthreads),
		.help	= "Number of Threads",
		.category = FIO_OPT_C_PROFILE,
		.group	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= NULL,
	},
};

/*
 * Fill our private options into the command line
 */
static int tb_prep_cmdline(void)
{
	/*
	 * tiobench uses size as MB, so multiply up
	 */
	size *= 1024 * 1024ULL;
	if (size)
		sprintf(sz_idx, "size=%llu", size);
	else
		strcpy(sz_idx, "size=4*1024*$mb_memory");

	sprintf(bs_idx, "bs=%u", bs);
	sprintf(loop_idx, "loops=%u", loops);

	if (dir)
		sprintf(dir_idx, "directory=%s", dir);
	else
		sprintf(dir_idx, "directory=./");

	sprintf(t_idx, "numjobs=%u", nthreads);
	return 0;
}

static struct profile_ops tiobench_profile = {
	.name		= "tiobench",
	.desc		= "tiotest/tiobench benchmark",
	.prep_cmd	= tb_prep_cmdline,
	.cmdline	= tb_opts,
	.options	= options,
	.opt_data	= &tiobench_options,
};

static void fio_init tiobench_register(void)
{
	if (register_profile(&tiobench_profile))
		log_err("fio: failed to register profile 'tiobench'\n");
}

static void fio_exit tiobench_unregister(void)
{
	unregister_profile(&tiobench_profile);
}
