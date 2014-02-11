#include "fio.h"
#include "profile.h"
#include "debug.h"
#include "flist.h"
#include "options.h"

static FLIST_HEAD(profile_list);

struct profile_ops *find_profile(const char *profile)
{
	struct profile_ops *ops = NULL;
	struct flist_head *n;

	flist_for_each(n, &profile_list) {
		ops = flist_entry(n, struct profile_ops, list);
		if (!strcmp(profile, ops->name))
			break;

		ops = NULL;
	}

	return ops;
}

int load_profile(const char *profile)
{
	struct profile_ops *ops;

	dprint(FD_PROFILE, "loading profile '%s'\n", profile);

	ops = find_profile(profile);
	if (ops) {
		if (ops->prep_cmd()) {
			log_err("fio: profile %s prep failed\n", profile);
			return 1;
		}
		add_job_opts(ops->cmdline, FIO_CLIENT_TYPE_CLI);
		return 0;
	}

	log_err("fio: profile '%s' not found\n", profile);
	return 1;
}

static int add_profile_options(struct profile_ops *ops)
{
	struct fio_option *o;

	if (!ops->options)
		return 0;

	o = ops->options;
	while (o->name) {
		o->prof_name = ops->name;
		o->prof_opts = ops->opt_data;
		if (add_option(o))
			return 1;
		o++;
	}

	return 0;
}

int register_profile(struct profile_ops *ops)
{
	int ret;

	dprint(FD_PROFILE, "register profile '%s'\n", ops->name);

	ret = add_profile_options(ops);
	if (!ret) {
		flist_add_tail(&ops->list, &profile_list);
		add_opt_posval("profile", ops->name, ops->desc);
		return 0;
	}

	invalidate_profile_options(ops->name);
	return ret;
}

void unregister_profile(struct profile_ops *ops)
{
	dprint(FD_PROFILE, "unregister profile '%s'\n", ops->name);
	flist_del(&ops->list);
	invalidate_profile_options(ops->name);
	del_opt_posval("profile", ops->name);
}

void profile_add_hooks(struct thread_data *td)
{
	struct profile_ops *ops;

	if (!exec_profile)
		return;

	ops = find_profile(exec_profile);
	if (!ops)
		return;

	if (ops->io_ops) {
		td->prof_io_ops = *ops->io_ops;
		td->flags |= TD_F_PROFILE_OPS;
	}
}

int profile_td_init(struct thread_data *td)
{
	struct prof_io_ops *ops = &td->prof_io_ops;

	if (ops->td_init)
		return ops->td_init(td);

	return 0;
}

void profile_td_exit(struct thread_data *td)
{
	struct prof_io_ops *ops = &td->prof_io_ops;

	if (ops->td_exit)
		ops->td_exit(td);
}
