/*
 * Code related to setting up a blkio cgroup
 */
#include <stdio.h>
#include <stdlib.h>
#include "fio.h"
#include "flist.h"
#include "cgroup.h"
#include "smalloc.h"

static struct flist_head *cgroup_list;
static struct fio_mutex *lock;

struct cgroup_member {
	struct flist_head list;
	char *root;
};

static void add_cgroup(const char *name)
{
	struct cgroup_member *cm;

	cm = smalloc(sizeof(*cm));
	INIT_FLIST_HEAD(&cm->list);
	cm->root = smalloc_strdup(name);

	fio_mutex_down(lock);

	if (!cgroup_list) {
		cgroup_list = smalloc(sizeof(struct flist_head));
		INIT_FLIST_HEAD(cgroup_list);
	}

	flist_add_tail(&cm->list, cgroup_list);
	fio_mutex_up(lock);
}

void cgroup_kill(void)
{
	struct flist_head *n, *tmp;
	struct cgroup_member *cm;

	fio_mutex_down(lock);
	if (!cgroup_list)
		goto out;

	flist_for_each_safe(n, tmp, cgroup_list) {
		cm = flist_entry(n, struct cgroup_member, list);
		rmdir(cm->root);
		flist_del(&cm->list);
		sfree(cm->root);
		sfree(cm);
	}

	sfree(cgroup_list);
	cgroup_list = NULL;
out:
	fio_mutex_up(lock);
}

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

static int cgroup_write_pid(struct thread_data *td, const char *root)
{
	char tmp[256];
	FILE *f;
	
	sprintf(tmp, "%s/tasks", root);
	f = fopen(tmp, "w");
	if (!f) {
		td_verror(td, errno, "cgroup open tasks");
		return 1;
	}

	fprintf(f, "%d", td->pid);
	fclose(f);
	return 0;

}

/*
 * Add pid to given class
 */
static int cgroup_add_pid(struct thread_data *td)
{
	char *root;
	int ret;

	root = get_cgroup_root(td);
	ret = cgroup_write_pid(td, root);
	free(root);
	return ret;
}

/*
 * Move pid to root class
 */
static int cgroup_del_pid(struct thread_data *td)
{
	return cgroup_write_pid(td, td->o.cgroup_root);
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
			goto err;
		}
	} else
		add_cgroup(root);

	if (td->o.cgroup_weight) {
		sprintf(tmp, "%s/blkio.weight", root);
		f = fopen(tmp, "w");
		if (!f) {
			td_verror(td, errno, "cgroup open weight");
			goto err;
		}

		fprintf(f, "%d", td->o.cgroup_weight);
		fclose(f);
	}

	free(root);

	if (cgroup_add_pid(td))
		return 1;

	return 0;
err:
	free(root);
	return 1;
}

void cgroup_shutdown(struct thread_data *td)
{
	if (cgroup_check_fs(td))
		return;
	if (!td->o.cgroup_weight && td->o.cgroup)
		return;

	cgroup_del_pid(td);
}


static void fio_init cgroup_init(void)
{
	lock = fio_mutex_init(1);
}

static void fio_exit cgroup_exit(void)
{
	fio_mutex_remove(lock);
}
