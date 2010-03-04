#include "../fio.h"
#include "../profile.h"
#include "../parse.h"

static unsigned long size;
static unsigned long loops;
static unsigned long bs;
static char *dir;

static const char *tb_opts[] = {
	"buffered=0", "size=4*1024*$mb_memory", "bs=4k", "timeout=600",
	"numjobs=4", "group_reporting", "thread", "overwrite=1",
	"filename=.fio.tio.1:.fio.tio.2:.fio.tio.3:.fio.tio.4",
	"name=seqwrite", "rw=write", "end_fsync=1",
	"name=randwrite", "stonewall", "rw=randwrite", "end_fsync=1",
	"name=seqread", "stonewall", "rw=read",
	"name=randread", "stonewall", "rw=randread", NULL,
};

static struct fio_option options[] = {
	{
		.name	= "size",
		.type	= FIO_OPT_INT,
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
		.name	= NULL,
	},
};

static struct profile_ops tiobench_profile = {
	.name		= "tiobench",
	.version	= FIO_PROFILE_VERSION,
	.def_ops	= tb_opts,
	.options	= options,
};

static void fio_init tiobench_register(void)
{
	register_profile(&tiobench_profile);
}

static void fio_exit tiobench_unregister(void)
{
	unregister_profile(&tiobench_profile);
}
