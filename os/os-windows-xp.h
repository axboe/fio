#define FIO_MAX_CPUS	MAXIMUM_PROCESSORS

typedef DWORD_PTR os_cpu_mask_t;

static inline int fio_setaffinity(int pid, os_cpu_mask_t cpumask)
{
	HANDLE h;
	BOOL bSuccess = FALSE;

	h = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SET_INFORMATION, TRUE, pid);
	if (h != NULL) {
		bSuccess = SetThreadAffinityMask(h, cpumask);
		if (!bSuccess)
			log_err("fio_setaffinity failed: failed to set thread affinity (pid %d, mask %.16llx)\n", pid, cpumask);

		CloseHandle(h);
	} else {
		log_err("fio_setaffinity failed: failed to get handle for pid %d\n", pid);
	}

	return (bSuccess)? 0 : -1;
}

static inline int fio_getaffinity(int pid, os_cpu_mask_t *mask)
{
	os_cpu_mask_t systemMask;

	HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);

	if (h != NULL) {
		GetProcessAffinityMask(h, mask, &systemMask);
		CloseHandle(h);
	} else {
		log_err("fio_getaffinity failed: failed to get handle for pid %d\n", pid);
		return -1;
	}

	return 0;
}

static inline void fio_cpu_clear(os_cpu_mask_t *mask, int cpu)
{
	*mask &= ~(1ULL << cpu);
}

static inline void fio_cpu_set(os_cpu_mask_t *mask, int cpu)
{
	*mask |= 1ULL << cpu;
}

static inline int fio_cpu_isset(os_cpu_mask_t *mask, int cpu)
{
	return (*mask & (1ULL << cpu)) != 0;
}

static inline int fio_cpu_count(os_cpu_mask_t *mask)
{
	return hweight64(*mask);
}

static inline int fio_cpuset_init(os_cpu_mask_t *mask)
{
	*mask = 0;
	return 0;
}

static inline int fio_cpuset_exit(os_cpu_mask_t *mask)
{
	return 0;
}
