#ifndef FIO_CGROUP_H
#define FIO_CGROUP_H

#ifdef FIO_HAVE_CGROUPS

struct cgroup_mnt {
	char *path;
	bool cgroup2;
};

int cgroup_setup(struct thread_data *, struct flist_head *, struct cgroup_mnt **);
void cgroup_shutdown(struct thread_data *, struct cgroup_mnt *);

void cgroup_kill(struct flist_head *list);

#else

struct cgroup_mnt;

static inline int cgroup_setup(struct thread_data *td, struct flist_head *list,
			       struct cgroup_mnt **mnt)
{
	td_verror(td, EINVAL, "cgroup_setup");
	return 1;
}

static inline void cgroup_shutdown(struct thread_data *td, struct cgroup_mnt *mnt)
{
}

static inline void cgroup_kill(struct flist_head *list)
{
}

#endif
#endif
