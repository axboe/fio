#include "../fio.h"
#include "../profile.h"

static const char *tb_opts[] = {
	"buffered=0", "size=4*1024*$mb_memory", "bs=4k", "timeout=600",
	"numjobs=4", "group_reporting", "thread", "overwrite=1",
	"filename=.fio.tio.1:.fio.tio.2:.fio.tio.3:.fio.tio.4",
	"name=seqwrite", "rw=write", "end_fsync=1",
	"name=randwrite", "stonewall", "rw=randwrite", "end_fsync=1",
	"name=seqread", "stonewall", "rw=read",
	"name=randread", "stonewall", "rw=randread", NULL,
};

static struct profile_ops tiobench_profile = {
	.name		= "tiobench",
	.version	= FIO_PROFILE_VERSION,
	.def_ops	= tb_opts,
};

static void fio_init tiobench_register(void)
{
	register_profile(&tiobench_profile);
}

static void fio_exit tiobench_unregister(void)
{
	unregister_profile(&tiobench_profile);
}
