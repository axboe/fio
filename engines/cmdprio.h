/*
 * IO priority handling declarations and helper functions common to the
 * libaio and io_uring engines.
 */

#ifndef FIO_CMDPRIO_H
#define FIO_CMDPRIO_H

#include "../fio.h"
#include "../optgroup.h"

/* read and writes only, no trim */
#define CMDPRIO_RWDIR_CNT 2

enum {
	CMDPRIO_MODE_NONE,
	CMDPRIO_MODE_PERC,
	CMDPRIO_MODE_BSSPLIT,
};

struct cmdprio_prio {
	int32_t prio;
	uint32_t perc;
	uint16_t clat_prio_index;
};

struct cmdprio_bsprio {
	uint64_t bs;
	uint32_t tot_perc;
	unsigned int nr_prios;
	struct cmdprio_prio *prios;
};

struct cmdprio_bsprio_desc {
	struct cmdprio_bsprio *bsprios;
	unsigned int nr_bsprios;
};

struct cmdprio_options {
	unsigned int percentage[CMDPRIO_RWDIR_CNT];
	unsigned int class[CMDPRIO_RWDIR_CNT];
	unsigned int level[CMDPRIO_RWDIR_CNT];
	unsigned int hint[CMDPRIO_RWDIR_CNT];
	char *bssplit_str;
};

#ifdef FIO_HAVE_IOPRIO_CLASS
#define CMDPRIO_OPTIONS(opt_struct, opt_group)					\
	{									\
		.name	= "cmdprio_percentage",					\
		.lname	= "high priority percentage",				\
		.type	= FIO_OPT_INT,						\
		.off1	= offsetof(opt_struct,					\
				   cmdprio_options.percentage[DDIR_READ]),	\
		.off2	= offsetof(opt_struct,					\
				   cmdprio_options.percentage[DDIR_WRITE]),	\
		.minval	= 0,							\
		.maxval	= 100,							\
		.help	= "Send high priority I/O this percentage of the time",	\
		.category = FIO_OPT_C_ENGINE,					\
		.group	= opt_group,						\
	},									\
	{									\
		.name	= "cmdprio_class",					\
		.lname	= "Asynchronous I/O priority class",			\
		.type	= FIO_OPT_INT,						\
		.off1	= offsetof(opt_struct,					\
				   cmdprio_options.class[DDIR_READ]),		\
		.off2	= offsetof(opt_struct,					\
				   cmdprio_options.class[DDIR_WRITE]),		\
		.help	= "Set asynchronous IO priority class",			\
		.minval	= IOPRIO_MIN_PRIO_CLASS + 1,				\
		.maxval	= IOPRIO_MAX_PRIO_CLASS,				\
		.interval = 1,							\
		.category = FIO_OPT_C_ENGINE,					\
		.group	= opt_group,						\
	},									\
	{									\
		.name	= "cmdprio_hint",					\
		.lname	= "Asynchronous I/O priority hint",			\
		.type	= FIO_OPT_INT,						\
		.off1	= offsetof(opt_struct,					\
				   cmdprio_options.hint[DDIR_READ]),		\
		.off2	= offsetof(opt_struct,					\
				   cmdprio_options.hint[DDIR_WRITE]),		\
		.help	= "Set asynchronous IO priority hint",			\
		.minval	= IOPRIO_MIN_PRIO_HINT,					\
		.maxval	= IOPRIO_MAX_PRIO_HINT,					\
		.interval = 1,							\
		.category = FIO_OPT_C_ENGINE,					\
		.group	= opt_group,						\
	},									\
	{									\
		.name	= "cmdprio",						\
		.lname	= "Asynchronous I/O priority level",			\
		.type	= FIO_OPT_INT,						\
		.off1	= offsetof(opt_struct,					\
				   cmdprio_options.level[DDIR_READ]),		\
		.off2	= offsetof(opt_struct,					\
				   cmdprio_options.level[DDIR_WRITE]),		\
		.help	= "Set asynchronous IO priority level",			\
		.minval	= IOPRIO_MIN_PRIO,					\
		.maxval	= IOPRIO_MAX_PRIO,					\
		.interval = 1,							\
		.category = FIO_OPT_C_ENGINE,					\
		.group	= opt_group,						\
	},									\
	{									\
		.name   = "cmdprio_bssplit",					\
		.lname  = "Priority percentage block size split",		\
		.type   = FIO_OPT_STR_STORE,					\
		.off1   = offsetof(opt_struct, cmdprio_options.bssplit_str),	\
		.help   = "Set priority percentages for different block sizes",	\
		.category = FIO_OPT_C_ENGINE,					\
		.group	= opt_group,						\
	}
#else
#define CMDPRIO_OPTIONS(opt_struct, opt_group)					\
	{									\
		.name	= "cmdprio_percentage",					\
		.lname	= "high priority percentage",				\
		.type	= FIO_OPT_UNSUPPORTED,					\
		.help	= "Platform does not support I/O priority classes",	\
	},									\
	{									\
		.name	= "cmdprio_class",					\
		.lname	= "Asynchronous I/O priority class",			\
		.type	= FIO_OPT_UNSUPPORTED,					\
		.help	= "Platform does not support I/O priority classes",	\
	},									\
	{									\
		.name	= "cmdprio_hint",					\
		.lname	= "Asynchronous I/O priority hint",			\
		.type	= FIO_OPT_UNSUPPORTED,					\
		.help	= "Platform does not support I/O priority classes",	\
	},									\
	{									\
		.name	= "cmdprio",						\
		.lname	= "Asynchronous I/O priority level",			\
		.type	= FIO_OPT_UNSUPPORTED,					\
		.help	= "Platform does not support I/O priority classes",	\
	},									\
	{									\
		.name   = "cmdprio_bssplit",					\
		.lname  = "Priority percentage block size split",		\
		.type	= FIO_OPT_UNSUPPORTED,					\
		.help	= "Platform does not support I/O priority classes",	\
	}
#endif

struct cmdprio {
	struct cmdprio_options *options;
	struct cmdprio_prio perc_entry[CMDPRIO_RWDIR_CNT];
	struct cmdprio_bsprio_desc bsprio_desc[CMDPRIO_RWDIR_CNT];
	unsigned int mode;
};

bool fio_cmdprio_set_ioprio(struct thread_data *td, struct cmdprio *cmdprio,
			    struct io_u *io_u);

void fio_cmdprio_cleanup(struct cmdprio *cmdprio);

int fio_cmdprio_init(struct thread_data *td, struct cmdprio *cmdprio,
		     struct cmdprio_options *options);

#endif
