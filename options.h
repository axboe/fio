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
	__FIO_OPT_G_DESC	= 0,
	__FIO_OPT_G_FILE,
	__FIO_OPT_G_IO,
	__FIO_OPT_G_IO_DDIR,
	__FIO_OPT_G_IO_BUF,
	__FIO_OPT_G_IO_ENG,
	__FIO_OPT_G_CACHE,
	__FIO_OPT_G_VERIFY,
	__FIO_OPT_G_ZONE,
	__FIO_OPT_G_MEM,
	__FIO_OPT_G_LOG,
	__FIO_OPT_G_ERR,
	__FIO_OPT_G_STAT,
	__FIO_OPT_G_CPU,
	__FIO_OPT_G_OS,
	__FIO_OPT_G_MISC,
	__FIO_OPT_G_RAND,
	__FIO_OPT_G_JOB,
	__FIO_OPT_G_NR,

	FIO_OPT_G_DESC		= (1U << __FIO_OPT_G_DESC),
	FIO_OPT_G_FILE		= (1U << __FIO_OPT_G_FILE),
	FIO_OPT_G_MISC		= (1U << __FIO_OPT_G_MISC),
	FIO_OPT_G_IO		= (1U << __FIO_OPT_G_IO),
	FIO_OPT_G_IO_DDIR	= (1U << __FIO_OPT_G_IO_DDIR),
	FIO_OPT_G_IO_BUF	= (1U << __FIO_OPT_G_IO_BUF),
	FIO_OPT_G_IO_ENG	= (1U << __FIO_OPT_G_IO_ENG),
	FIO_OPT_G_RAND		= (1U << __FIO_OPT_G_RAND),
	FIO_OPT_G_OS		= (1U << __FIO_OPT_G_OS),
	FIO_OPT_G_MEM		= (1U << __FIO_OPT_G_MEM),
	FIO_OPT_G_VERIFY	= (1U << __FIO_OPT_G_VERIFY),
	FIO_OPT_G_CPU		= (1U << __FIO_OPT_G_CPU),
	FIO_OPT_G_LOG		= (1U << __FIO_OPT_G_LOG),
	FIO_OPT_G_ZONE		= (1U << __FIO_OPT_G_ZONE),
	FIO_OPT_G_CACHE		= (1U << __FIO_OPT_G_CACHE),
	FIO_OPT_G_STAT		= (1U << __FIO_OPT_G_STAT),
	FIO_OPT_G_ERR		= (1U << __FIO_OPT_G_ERR),
	FIO_OPT_G_JOB		= (1U << __FIO_OPT_G_JOB),
	FIO_OPT_G_INVALID	= (1U << __FIO_OPT_G_NR),
};

extern struct opt_group *opt_group_from_mask(unsigned int *mask);

#endif
