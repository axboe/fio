#include "../fio.h"
#include "../profile.h"
#include "../parse.h"

static unsigned long long size;
static unsigned int loops = 1;
static unsigned int bs = 4096;
static unsigned int nthreads = 1;
static char *dir;

char sz_idx[80], bs_idx[80], loop_idx[80], dir_idx[80], t_idx[80];

static const char *tb_opts[] = {
	"buffered=0", sz_idx, bs_idx, loop_idx, dir_idx, t_idx,
	"timeout=600", "group_reporting", "thread", "overwrite=1",
	"filename=.fio.tio.1:.fio.tio.2:.fio.tio.3:.fio.tio.4",
	"name=seqwrite", "rw=write", "end_fsync=1",
	"name=randwrite", "stonewall", "rw=randwrite", "end_fsync=1",
	"name=seqread", "stonewall", "rw=read",
	"name=randread", "stonewall", "rw=randread", NULL,
};

static struct fio_option options[] = {
	{
		.name	= "size",
		.type	= FIO_OPT_STR_VAL,
		.roff1	= &size,
		.help	= "Size in MB",
	},
	{
		.name	= "block",
		.type	= FIO_OPT_INT,
		.roff1	= &bs,
		.help	= "Block size in bytes",
		.def	= "4k",
	},
	{
		.name	= "numruns",
		.type	= FIO_OPT_INT,
		.roff1	= &loops,
		.help	= "Number of runs",
	},
	{
		.name	= "dir",
		.type	= FIO_OPT_STR_STORE,
		.roff1	= &dir,
		.help	= "Test directory",
	},
	{
		.name	= "threads",
		.type	= FIO_OPT_INT,
		.roff1	= &nthreads,
		.help	= "Number of Threads",
	},
	{
		.name	= NULL,
	},
};

/*
 * Fill our private options into the command line
 */
static void tb_prep_cmdline(void)
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
}

static struct profile_ops tiobench_profile = {
	.name		= "tiobench",
	.desc		= "tiotest/tiobench benchmark",
	.options	= options,
	.prep_cmd	= tb_prep_cmdline,
	.cmdline	= tb_opts,
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
