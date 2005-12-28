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

#endif
