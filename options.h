#ifndef FIO_OPTION_H
#define FIO_OPTION_H

#define FIO_MAX_OPTS		512

#include <string.h>
#include <inttypes.h>
#include "parse.h"
#include "lib/types.h"

int add_option(const struct fio_option *);
void invalidate_profile_options(const char *);
extern char *exec_profile;

void add_opt_posval(const char *, const char *, const char *);
void del_opt_posval(const char *, const char *);
struct thread_data;
void fio_options_free(struct thread_data *);
void fio_dump_options_free(struct thread_data *);
char *get_next_str(char **ptr);
int get_max_str_idx(char *input);
char* get_name_by_idx(char *input, int index);
int set_name_idx(char *, size_t, char *, int, bool);

extern char client_sockaddr_str[];  /* used with --client option */

extern struct fio_option fio_options[FIO_MAX_OPTS];

extern bool __fio_option_is_set(struct thread_options *, unsigned int off);

#define fio_option_is_set(__td, name)					\
({									\
	const unsigned int off = offsetof(struct thread_options, name);	\
	bool __r = __fio_option_is_set((__td), off);			\
	__r;								\
})

extern void fio_option_mark_set(struct thread_options *,
				const struct fio_option *);

static inline bool o_match(const struct fio_option *o, const char *opt)
{
	if (!strcmp(o->name, opt))
		return true;
	else if (o->alias && !strcmp(o->alias, opt))
		return true;

	return false;
}

extern struct fio_option *find_option(struct fio_option *, const char *);
extern const struct fio_option *
find_option_c(const struct fio_option *, const char *);
extern struct fio_option *fio_option_find(const char *);
extern unsigned int fio_get_kb_base(void *);

#endif
