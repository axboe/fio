/*
 * Code related to setting up a blkio cgroup
 */
#include <stdio.h>
#include <stdlib.h>
#include "fio.h"
#include "cgroup.h"

/*
 * Check if the given root appears valid
 */
static int cgroup_check_fs(struct thread_data *td)
{
	struct stat sb;
	char tmp[256];

	sprintf(tmp, "%s/tasks", td->o.cgroup_root);
	return stat(tmp, &sb);
}

static char *get_cgroup_root(struct thread_data *td)
{
	char *str = malloc(64);

	if (td->o.cgroup)
		sprintf(str, "%s/%s", td->o.cgroup_root, td->o.cgroup);
	else
		sprintf(str, "%s/%s", td->o.cgroup_root, td->o.name);

	return str;
}

/*
 * Add pid to given class
 */
static int cgroup_add_pid(struct thread_data *td)
{
	char *root, tmp[256];
	FILE *f;

	root = get_cgroup_root(td);
	sprintf(tmp, "%s/tasks", root);

	f = fopen(tmp, "w");
	if (!f) {
		td_verror(td, errno, "cgroup open tasks");
		return 1;
	}

	fprintf(f, "%d", td->pid);
	fclose(f);
	free(root);
	return 0;
}

/*
 * Move pid to root class
 */
static int cgroup_del_pid(struct thread_data *td)
{
	char tmp[256];
	FILE *f;

	sprintf(tmp, "%s/tasks", td->o.cgroup_root);
	f = fopen(tmp, "w");
	if (!f) {
		td_verror(td, errno, "cgroup open tasks");
		return 1;
	}

	fprintf(f, "%d", td->pid);
	fclose(f);
	return 0;
}


int cgroup_setup(struct thread_data *td)
{
	char *root, tmp[256];
	FILE *f;

	if (cgroup_check_fs(td)) {
		log_err("fio: blkio cgroup mount point %s not valid\n",
							td->o.cgroup_root);
		return 1;
	}

	/*
	 * Create container, if it doesn't exist
	 */
	root = get_cgroup_root(td);
	if (mkdir(root, 0755) < 0) {
		int __e = errno;

		if (__e != EEXIST) {
			td_verror(td, __e, "cgroup mkdir");
			return 1;
		}
	} else
		td->o.cgroup_was_created = 1;

	sprintf(tmp, "%s/blkio.weight", root);
	f = fopen(tmp, "w");
	if (!f) {
		td_verror(td, errno, "cgroup open weight");
		return 1;
	}

	fprintf(f, "%d", td->o.cgroup_weight);
	fclose(f);
	free(root);

	if (cgroup_add_pid(td))
		return 1;

	return 0;
}

void cgroup_shutdown(struct thread_data *td)
{
	if (cgroup_check_fs(td))
		return;
	if (!td->o.cgroup_weight)
		return;

	cgroup_del_pid(td);

	if (td->o.cgroup_was_created) {
		char *root;

		root = get_cgroup_root(td);
		rmdir(root);
		free(root);
	}
}
