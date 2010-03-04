#ifndef FIO_PROFILE_H
#define FIO_PROFILE_H

#include "flist.h"

#define FIO_PROFILE_VERSION	1

struct profile_ops {
	struct flist_head list;
	char name[32];
	int version;
	int flags;

	const char **def_ops;
	struct fio_option *options;
};

void register_profile(struct profile_ops *);
void unregister_profile(struct profile_ops *);
int load_profile(const char *);

#endif
