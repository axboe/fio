#ifndef FIO_OPTION_H
#define FIO_OPTION_H

#include "parse.h"
#include "flist.h"

#define td_var_offset(var)	((size_t) &((struct thread_options *)0)->var)

struct ext_option {
	struct flist_head list;
	struct fio_option o;
};

void register_option(struct ext_option *);

#endif
