#ifndef FIO_OPTION_H
#define FIO_OPTION_H

#define FIO_MAX_OPTS		512

#include <string.h>
#include "parse.h"
#include "flist.h"

#define td_var_offset(var)	((size_t) &((struct thread_options *)0)->var)

int add_option(struct fio_option *);
void invalidate_profile_options(const char *);
extern char *exec_profile;

void add_opt_posval(const char *, const char *, const char *);
void del_opt_posval(const char *, const char *);
struct thread_data;
void fio_options_free(struct thread_data *);
char *get_name_idx(char *, int);
int set_name_idx(char *, char *, int);

extern struct fio_option fio_options[FIO_MAX_OPTS];

static inline int o_match(struct fio_option *o, const char *opt)
{
	if (!strcmp(o->name, opt))
		return 1;
	else if (o->alias && !strcmp(o->alias, opt))
		return 1;

	return 0;
}

static inline struct fio_option *find_option(struct fio_option *options,
					     const char *opt)
{
	struct fio_option *o;

	for (o = &options[0]; o->name; o++)
		if (o_match(o, opt))
			return o;

	return NULL;
}

struct opt_group {
	const char *name;
	unsigned int mask;
};

enum opt_category {
	__FIO_OPT_C_GENERAL	= 0,
	__FIO_OPT_C_IO,
	__FIO_OPT_C_FILE,
	__FIO_OPT_C_STAT,
	__FIO_OPT_C_LOG,
	__FIO_OPT_C_PROFILE,
	__FIO_OPT_C_ENGINE,
	__FIO_OPT_C_NR,

	FIO_OPT_C_GENERAL	= (1U << __FIO_OPT_C_GENERAL),
	FIO_OPT_C_IO		= (1U << __FIO_OPT_C_IO),
	FIO_OPT_C_FILE		= (1U << __FIO_OPT_C_FILE),
	FIO_OPT_C_STAT		= (1U << __FIO_OPT_C_STAT),
	FIO_OPT_C_LOG		= (1U << __FIO_OPT_C_LOG),
	FIO_OPT_C_PROFILE	= (1U << __FIO_OPT_C_PROFILE),
	FIO_OPT_C_ENGINE	= (1U << __FIO_OPT_C_ENGINE),
	FIO_OPT_C_INVALID	= (1U << __FIO_OPT_C_NR),
};

enum opt_category_group {
	__FIO_OPT_G_RATE	= 0,
	__FIO_OPT_G_ZONE,
	__FIO_OPT_G_RWMIX,
	__FIO_OPT_G_VERIFY,
	__FIO_OPT_G_TRIM,
	__FIO_OPT_G_IOLOG,
	__FIO_OPT_G_IO_DEPTH,
	__FIO_OPT_G_IO_FLOW,
	__FIO_OPT_G_DESC,
	__FIO_OPT_G_FILENAME,
	__FIO_OPT_G_IO_BASIC,
	__FIO_OPT_G_CGROUP,
	__FIO_OPT_G_RUNTIME,
	__FIO_OPT_G_PROCESS,
	__FIO_OPT_G_CRED,
	__FIO_OPT_G_CLOCK,
	__FIO_OPT_G_IO_TYPE,
	__FIO_OPT_G_THINKTIME,
	__FIO_OPT_G_RANDOM,
	__FIO_OPT_G_IO_BUF,
	__FIO_OPT_G_TIOBENCH,
	__FIO_OPT_G_ERR,
	__FIO_OPT_G_E4DEFRAG,
	__FIO_OPT_G_NETIO,
	__FIO_OPT_G_LIBAIO,
	__FIO_OPT_G_ACT,
	__FIO_OPT_G_LATPROF,
        __FIO_OPT_G_RBD,
	__FIO_OPT_G_NR,

	FIO_OPT_G_RATE		= (1U << __FIO_OPT_G_RATE),
	FIO_OPT_G_ZONE		= (1U << __FIO_OPT_G_ZONE),
	FIO_OPT_G_RWMIX		= (1U << __FIO_OPT_G_RWMIX),
	FIO_OPT_G_VERIFY	= (1U << __FIO_OPT_G_VERIFY),
	FIO_OPT_G_TRIM		= (1U << __FIO_OPT_G_TRIM),
	FIO_OPT_G_IOLOG		= (1U << __FIO_OPT_G_IOLOG),
	FIO_OPT_G_IO_DEPTH	= (1U << __FIO_OPT_G_IO_DEPTH),
	FIO_OPT_G_IO_FLOW	= (1U << __FIO_OPT_G_IO_FLOW),
	FIO_OPT_G_DESC		= (1U << __FIO_OPT_G_DESC),
	FIO_OPT_G_FILENAME	= (1U << __FIO_OPT_G_FILENAME),
	FIO_OPT_G_IO_BASIC	= (1U << __FIO_OPT_G_IO_BASIC),
	FIO_OPT_G_CGROUP	= (1U << __FIO_OPT_G_CGROUP),
	FIO_OPT_G_RUNTIME	= (1U << __FIO_OPT_G_RUNTIME),
	FIO_OPT_G_PROCESS	= (1U << __FIO_OPT_G_PROCESS),
	FIO_OPT_G_CRED		= (1U << __FIO_OPT_G_CRED),
	FIO_OPT_G_CLOCK		= (1U << __FIO_OPT_G_CLOCK),
	FIO_OPT_G_IO_TYPE	= (1U << __FIO_OPT_G_IO_TYPE),
	FIO_OPT_G_THINKTIME	= (1U << __FIO_OPT_G_THINKTIME),
	FIO_OPT_G_RANDOM	= (1U << __FIO_OPT_G_RANDOM),
	FIO_OPT_G_IO_BUF	= (1U << __FIO_OPT_G_IO_BUF),
	FIO_OPT_G_TIOBENCH	= (1U << __FIO_OPT_G_TIOBENCH),
	FIO_OPT_G_ERR		= (1U << __FIO_OPT_G_ERR),
	FIO_OPT_G_E4DEFRAG	= (1U << __FIO_OPT_G_E4DEFRAG),
	FIO_OPT_G_NETIO		= (1U << __FIO_OPT_G_NETIO),
	FIO_OPT_G_LIBAIO	= (1U << __FIO_OPT_G_LIBAIO),
	FIO_OPT_G_ACT		= (1U << __FIO_OPT_G_ACT),
	FIO_OPT_G_LATPROF	= (1U << __FIO_OPT_G_LATPROF),
	FIO_OPT_G_RBD		= (1U << __FIO_OPT_G_RBD),
	FIO_OPT_G_INVALID	= (1U << __FIO_OPT_G_NR),
};

extern struct opt_group *opt_group_from_mask(unsigned int *mask);
extern struct opt_group *opt_group_cat_from_mask(unsigned int *mask);
extern struct fio_option *fio_option_find(const char *name);
extern unsigned int fio_get_kb_base(void *);

#endif
