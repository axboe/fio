#ifndef FIO_OPTION_H
#define FIO_OPTION_H

#define FIO_MAX_OPTS		512

#include "parse.h"
#include "flist.h"

#define td_var_offset(var)	((size_t) &((struct thread_options *)0)->var)

int add_option(struct fio_option *);
void invalidate_profile_options(const char *);
extern char *exec_profile;

#endif
