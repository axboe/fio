#ifndef FIO_OPTION_H
#define FIO_OPTION_H

#define FIO_MAX_OPTS		512

#include <string.h>
#include <inttypes.h>
#include "parse.h"
#include "flist.h"
#include "lib/types.h"

#define td_var_offset(var)	((size_t) &((struct thread_options *)0)->var)

int add_option(struct fio_option *);
void invalidate_profile_options(const char *);
extern char *exec_profile;

void add_opt_posval(const char *, const char *, const char *);
void del_opt_posval(const char *, const char *);
struct thread_data;
void fio_options_free(struct thread_data *);
char *get_name_idx(char *, int);
int set_name_idx(char *, size_t, char *, int, bool);

extern char client_sockaddr_str[];  /* used with --client option */

extern struct fio_option fio_options[FIO_MAX_OPTS];

extern bool __fio_option_is_set(struct thread_options *, unsigned int off);

#define fio_option_is_set(__td, name)					\
({									\
	const unsigned int off = td_var_offset(name);			\
	bool __r = __fio_option_is_set((__td), off);			\
	__r;								\
})

extern void fio_option_mark_set(struct thread_options *, struct fio_option *);

static inline bool o_match(struct fio_option *o, const char *opt)
{
	if (!strcmp(o->name, opt))
		return true;
	else if (o->alias && !strcmp(o->alias, opt))
		return true;

	return false;
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

extern struct fio_option *fio_option_find(const char *name);
extern unsigned int fio_get_kb_base(void *);

#endif
