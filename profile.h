#ifndef FIO_PROFILE_H
#define FIO_PROFILE_H

#include "flist.h"

/*
 * Functions for overriding internal fio io_u functions
 */
struct prof_io_ops {
	int (*td_init)(struct thread_data *);
	void (*td_exit)(struct thread_data *);

	int (*io_u_lat)(struct thread_data *, uint64_t);
};

struct profile_ops {
	struct flist_head list;
	char name[32];
	char desc[64];
	int flags;

	/*
	 * Profile specific options
	 */
	struct fio_option *options;
	void *opt_data;

	/*
	 * Called after parsing options, to prepare 'cmdline'
	 */
	int (*prep_cmd)(void);

	/*
	 * The complete command line
	 */
	const char **cmdline;

	struct prof_io_ops *io_ops;
};

int register_profile(struct profile_ops *);
void unregister_profile(struct profile_ops *);
int load_profile(const char *);
struct profile_ops *find_profile(const char *);
void profile_add_hooks(struct thread_data *);

int profile_td_init(struct thread_data *);
void profile_td_exit(struct thread_data *);

#endif
