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
	__FIO_OPT_G_FILE	= 1,
	__FIO_OPT_G_MISC	= 2,
	__FIO_OPT_G_IO		= 3,
	__FIO_OPT_G_IO_DDIR	= 4,
	__FIO_OPT_G_IO_BUF	= 5,
	__FIO_OPT_G_RAND	= 6,
	__FIO_OPT_G_OS		= 7,
	__FIO_OPT_G_MEM		= 8,
	__FIO_OPT_G_VERIFY	= 9,
	__FIO_OPT_G_CPU		= 10,
	__FIO_OPT_G_LOG		= 11,
	__FIO_OPT_G_ZONE	= 12,
	__FIO_OPT_G_CACHE	= 13,
	__FIO_OPT_G_STAT	= 14,
	__FIO_OPT_G_ERR		= 15,
	__FIO_OPT_G_JOB		= 16,
	__FIO_OPT_G_NR		= 17,

	FIO_OPT_G_DESC		= (1U << __FIO_OPT_G_DESC),
	FIO_OPT_G_FILE		= (1U << __FIO_OPT_G_FILE),
	FIO_OPT_G_MISC		= (1U << __FIO_OPT_G_MISC),
	FIO_OPT_G_IO		= (1U << __FIO_OPT_G_IO),
	FIO_OPT_G_IO_DDIR	= (1U << __FIO_OPT_G_IO_DDIR),
	FIO_OPT_G_IO_BUF	= (1U << __FIO_OPT_G_IO_BUF),
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
