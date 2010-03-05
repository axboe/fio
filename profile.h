#ifndef FIO_PROFILE_H
#define FIO_PROFILE_H

#include "flist.h"

struct profile_ops {
	struct flist_head list;
	char name[32];
	char desc[64];
	int flags;

	/*
	 * Profile specific options
	 */
	struct fio_option *options;

	/*
	 * Called after parsing options, to prepare 'cmdline'
	 */
	void (*prep_cmd)(void);

	/*
	 * The complete command line
	 */
	const char **cmdline;
};

int register_profile(struct profile_ops *);
void unregister_profile(struct profile_ops *);
int load_profile(const char *);

#endif
