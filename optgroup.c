#include <stdio.h>
#include <inttypes.h>
#include "optgroup.h"

/*
 * Option grouping
 */
static const struct opt_group fio_opt_groups[] = {
	{
		.name	= "General",
		.mask	= FIO_OPT_C_GENERAL,
	},
	{
		.name	= "I/O",
		.mask	= FIO_OPT_C_IO,
	},
	{
		.name	= "File",
		.mask	= FIO_OPT_C_FILE,
	},
	{
		.name	= "Statistics",
		.mask	= FIO_OPT_C_STAT,
	},
	{
		.name	= "Logging",
		.mask	= FIO_OPT_C_LOG,
	},
	{
		.name	= "Profiles",
		.mask	= FIO_OPT_C_PROFILE,
	},
	{
		.name	= "I/O engines",
		.mask	= FIO_OPT_C_ENGINE,
	},
	{
		.name	= NULL,
	},
};

static const struct opt_group fio_opt_cat_groups[] = {
	{
		.name	= "Rate",
		.mask	= FIO_OPT_G_RATE,
	},
	{
		.name	= "Zone",
		.mask	= FIO_OPT_G_ZONE,
	},
	{
		.name	= "Read/write mix",
		.mask	= FIO_OPT_G_RWMIX,
	},
	{
		.name	= "Verify",
		.mask	= FIO_OPT_G_VERIFY,
	},
	{
		.name	= "Trim",
		.mask	= FIO_OPT_G_TRIM,
	},
	{
		.name	= "I/O Logging",
		.mask	= FIO_OPT_G_IOLOG,
	},
	{
		.name	= "I/O Depth",
		.mask	= FIO_OPT_G_IO_DEPTH,
	},
	{
		.name	= "I/O Flow",
		.mask	= FIO_OPT_G_IO_FLOW,
	},
	{
		.name	= "Description",
		.mask	= FIO_OPT_G_DESC,
	},
	{
		.name	= "Filename",
		.mask	= FIO_OPT_G_FILENAME,
	},
	{
		.name	= "General I/O",
		.mask	= FIO_OPT_G_IO_BASIC,
	},
	{
		.name	= "Cgroups",
		.mask	= FIO_OPT_G_CGROUP,
	},
	{
		.name	= "Runtime",
		.mask	= FIO_OPT_G_RUNTIME,
	},
	{
		.name	= "Process",
		.mask	= FIO_OPT_G_PROCESS,
	},
	{
		.name	= "Job credentials / priority",
		.mask	= FIO_OPT_G_CRED,
	},
	{
		.name	= "Clock settings",
		.mask	= FIO_OPT_G_CLOCK,
	},
	{
		.name	= "I/O Type",
		.mask	= FIO_OPT_G_IO_TYPE,
	},
	{
		.name	= "I/O Thinktime",
		.mask	= FIO_OPT_G_THINKTIME,
	},
	{
		.name	= "Randomizations",
		.mask	= FIO_OPT_G_RANDOM,
	},
	{
		.name	= "I/O buffers",
		.mask	= FIO_OPT_G_IO_BUF,
	},
	{
		.name	= "Tiobench profile",
		.mask	= FIO_OPT_G_TIOBENCH,
	},
	{
		.name	= "Error handling",
		.mask	= FIO_OPT_G_ERR,
	},
	{
		.name	= "Ext4 defrag I/O engine", /* e4defrag */
		.mask	= FIO_OPT_G_E4DEFRAG,
	},
	{
		.name	= "Network I/O engine", /* net */
		.mask	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "RDMA I/O engine", /* rdma */
		.mask	= FIO_OPT_G_RDMA,
	},
	{
		.name	= "libaio I/O engine", /* libaio */
		.mask	= FIO_OPT_G_LIBAIO,
	},
	{
		.name	= "ACT Aerospike like benchmark profile",
		.mask	= FIO_OPT_G_ACT,
	},
	{
		.name	= "Latency profiling",
		.mask	= FIO_OPT_G_LATPROF,
	},
	{
		.name	= "RBD I/O engine", /* rbd */
		.mask	= FIO_OPT_G_RBD,
	},
	{
		.name	= "GlusterFS I/O engine", /* gfapi,gfapi_async */
		.mask	= FIO_OPT_G_GFAPI,
	},
	{
		.name	= "MTD I/O engine", /* mtd */
		.mask	= FIO_OPT_G_MTD,
	},
	{
		.name	= "libhdfs I/O engine", /* libhdfs */
		.mask	= FIO_OPT_G_HDFS,
	},
	{
		.name	= NULL,
	},
};

static const struct opt_group *group_from_mask(const struct opt_group *ogs,
					       uint64_t *mask,
					       uint64_t inv_mask)
{
	int i;

	if (*mask == inv_mask || !*mask)
		return NULL;

	for (i = 0; ogs[i].name; i++) {
		const struct opt_group *og = &ogs[i];

		if (*mask & og->mask) {
			*mask &= ~(og->mask);
			return og;
		}
	}

	return NULL;
}

const struct opt_group *opt_group_from_mask(uint64_t *mask)
{
	return group_from_mask(fio_opt_groups, mask, FIO_OPT_C_INVALID);
}

const struct opt_group *opt_group_cat_from_mask(uint64_t *mask)
{
	return group_from_mask(fio_opt_cat_groups, mask, FIO_OPT_G_INVALID);
}
