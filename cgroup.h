#ifndef FIO_CGROUP_H
#define FIO_CGROUP_H

#ifdef FIO_HAVE_CGROUPS

int cgroup_setup(struct thread_data *, struct flist_head *, char **);
void cgroup_shutdown(struct thread_data *, char **);

void cgroup_kill(struct flist_head *list);

#else

static inline int cgroup_setup(struct thread_data *td, struct flist_head *list,
			       char **mnt)
{
	td_verror(td, EINVAL, "cgroup_setup");
	return 1;
}

static inline void cgroup_shutdown(struct thread_data *td, char **mnt)
{
}

static inline void cgroup_kill(struct flist_head *list)
{
}

#endif
#endif
