#ifndef FIO_OS_FREEBSD_H
#define FIO_OS_FREEBSD_H

#undef FIO_HAVE_LIBAIO
#define FIO_HAVE_POSIXAIO
#undef FIO_HAVE_FADVISE
#undef FIO_HAVE_CPU_AFFINITY
#undef FIO_HAVE_DISK_UTIL
#undef FIO_HAVE_SGIO

#define OS_MAP_ANON		(MAP_ANON)

typedef unsigned long os_cpu_mask_t;

/*
 * FIXME
 */
static inline int blockdev_size(int fd, unsigned long long *bytes)
{
	return 1;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM };
	unsigned long long mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

#endif
