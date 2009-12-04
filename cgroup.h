#ifndef FIO_CGROUP_H
#define FIO_CGROUP_H

#ifdef FIO_HAVE_CGROUPS

int cgroup_setup(struct thread_data *td);
void cgroup_shutdown(struct thread_data *td);

void cgroup_kill(void);

#else

static inline int cgroup_setup(struct thread_data *td)
{
	td_verror(td, EINVAL, "cgroup_setup");
	return 1;
}

static inline void cgroup_shutdown(struct thread_data *td)
{
}

void cgroup_kill(void)
{
}

#endif
#endif
