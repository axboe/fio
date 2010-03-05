#include "fio.h"
#include "profile.h"
#include "debug.h"
#include "flist.h"
#include "options.h"

static FLIST_HEAD(profile_list);

int load_profile(const char *profile)
{
	struct profile_ops *ops;
	struct flist_head *n;

	dprint(FD_PROFILE, "loading profile '%s'\n", profile);

	flist_for_each(n, &profile_list) {
		ops = flist_entry(n, struct profile_ops, list);
		if (!strcmp(profile, ops->name))
			break;

		ops = NULL;
	}

	if (ops) {
		ops->prep_cmd();
		add_job_opts(ops->cmdline);
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
	flist_add_tail(&ops->list, &profile_list);
	ret = add_profile_options(ops);
	if (ret)
		invalidate_profile_options(ops->name);

	return ret;
}

void unregister_profile(struct profile_ops *ops)
{
	dprint(FD_PROFILE, "unregister profile '%s'\n", ops->name);
	flist_del(&ops->list);
	invalidate_profile_options(ops->name);
}
