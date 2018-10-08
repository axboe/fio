#ifndef FIO_OS_ANDROID_H
#define FIO_OS_ANDROID_H

#define	FIO_OS	os_android

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/vfs.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <linux/unistd.h>
#include <linux/major.h>
#include <asm/byteorder.h>

#include "./os-linux-syscall.h"
#include "../file.h"

#ifndef __has_builtin         // Optional of course.
  #define __has_builtin(x) 0  // Compatibility with non-clang compilers.
#endif

#define FIO_HAVE_DISK_UTIL
#define FIO_HAVE_IOSCHED_SWITCH
#define FIO_HAVE_IOPRIO
#define FIO_HAVE_IOPRIO_CLASS
#define FIO_HAVE_ODIRECT
#define FIO_HAVE_HUGETLB
#define FIO_HAVE_BLKTRACE
#define FIO_HAVE_CL_SIZE
#define FIO_HAVE_CGROUPS
#define FIO_HAVE_FS_STAT
#define FIO_HAVE_TRIM
#define FIO_HAVE_GETTID
#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_E4_ENG
#define FIO_HAVE_BYTEORDER_FUNCS
#define FIO_HAVE_MMAP_HUGE
#define FIO_NO_HAVE_SHM_H

#define OS_MAP_ANON		MAP_ANONYMOUS

#ifndef POSIX_MADV_DONTNEED
#define posix_madvise   madvise
#define POSIX_MADV_DONTNEED MADV_DONTNEED
#define POSIX_MADV_SEQUENTIAL	MADV_SEQUENTIAL
#define POSIX_MADV_RANDOM	MADV_RANDOM
#endif

#ifdef MADV_REMOVE
#define FIO_MADV_FREE	MADV_REMOVE
#endif
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000 /* arch specific */
#endif

#ifndef CONFIG_NO_SHM
/*
 * Bionic doesn't support SysV shared memeory, so implement it using ashmem
 */
#include <stdio.h>
#include <linux/ashmem.h>
#include <linux/shm.h>
#define shmid_ds shmid64_ds
#define SHM_HUGETLB    04000

#define ASHMEM_DEVICE	"/dev/ashmem"

static inline int shmctl(int __shmid, int __cmd, struct shmid_ds *__buf)
{
	int ret=0;
	if (__cmd == IPC_RMID)
	{
		int length = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
		struct ashmem_pin pin = {0 , length};
		ret = ioctl(__shmid, ASHMEM_UNPIN, &pin);
		close(__shmid);
	}
	return ret;
}

static inline int shmget(key_t __key, size_t __size, int __shmflg)
{
	int fd,ret;
	char keybuf[11];

	fd = open(ASHMEM_DEVICE, O_RDWR);
	if (fd < 0)
		return fd;

	sprintf(keybuf,"%d",__key);
	ret = ioctl(fd, ASHMEM_SET_NAME, keybuf);
	if (ret < 0)
		goto error;

	/* Stores size in first 8 bytes, allocate extra space */
	ret = ioctl(fd, ASHMEM_SET_SIZE, __size + sizeof(uint64_t));
	if (ret < 0)
		goto error;

	return fd;

error:
	close(fd);
	return ret;
}

static inline void *shmat(int __shmid, const void *__shmaddr, int __shmflg)
{
	size_t size = ioctl(__shmid, ASHMEM_GET_SIZE, NULL);
	/* Needs to be 8-byte aligned to prevent SIGBUS on 32-bit ARM */
	uint64_t *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, __shmid, 0);
	/* Save size at beginning of buffer, for use with munmap */
	*ptr = size;
	return ptr + 1;
}

static inline int shmdt (const void *__shmaddr)
{
	/* Find mmap size which we stored at the beginning of the buffer */
	uint64_t *ptr = (uint64_t *)__shmaddr - 1;
	size_t size = *ptr;
	return munmap(ptr, size);
}
#endif

#define SPLICE_DEF_SIZE	(64*1024)

enum {
	IOPRIO_CLASS_NONE,
	IOPRIO_CLASS_RT,
	IOPRIO_CLASS_BE,
	IOPRIO_CLASS_IDLE,
};

enum {
	IOPRIO_WHO_PROCESS = 1,
	IOPRIO_WHO_PGRP,
	IOPRIO_WHO_USER,
};

#define IOPRIO_BITS		16
#define IOPRIO_CLASS_SHIFT	13

#define IOPRIO_MIN_PRIO		0	/* highest priority */
#define IOPRIO_MAX_PRIO		7	/* lowest priority */

#define IOPRIO_MIN_PRIO_CLASS	0
#define IOPRIO_MAX_PRIO_CLASS	3

static inline int ioprio_set(int which, int who, int ioprio_class, int ioprio)
{
	/*
	 * If no class is set, assume BE
	 */
	if (!ioprio_class)
		ioprio_class = IOPRIO_CLASS_BE;

	ioprio |= ioprio_class << IOPRIO_CLASS_SHIFT;
	return syscall(__NR_ioprio_set, which, who, ioprio);
}

#ifndef BLKGETSIZE64
#define BLKGETSIZE64	_IOR(0x12,114,size_t)
#endif

#ifndef BLKFLSBUF
#define BLKFLSBUF	_IO(0x12,97)
#endif

#ifndef BLKDISCARD
#define BLKDISCARD	_IO(0x12,119)
#endif

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ioctl(f->fd, BLKFLSBUF);
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	if (!ioctl(f->fd, BLKGETSIZE64, bytes))
		return 0;

	return errno;
}

static inline unsigned long long os_phys_mem(void)
{
	long pagesize, pages;

	pagesize = sysconf(_SC_PAGESIZE);
	pages = sysconf(_SC_PHYS_PAGES);
	if (pages == -1 || pagesize == -1)
		return 0;

	return (unsigned long long) pages * (unsigned long long) pagesize;
}

#ifdef O_NOATIME
#define FIO_O_NOATIME	O_NOATIME
#else
#define FIO_O_NOATIME	0
#endif

/* Check for GCC or Clang byte swap intrinsics */
#if (__has_builtin(__builtin_bswap16) && __has_builtin(__builtin_bswap32) \
     && __has_builtin(__builtin_bswap64)) || (__GNUC__ > 4 \
     || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)) /* fio_swapN */
#define fio_swap16(x)	__builtin_bswap16(x)
#define fio_swap32(x)	__builtin_bswap32(x)
#define fio_swap64(x)	__builtin_bswap64(x)
#else
#include <byteswap.h>
#define fio_swap16(x)	bswap_16(x)
#define fio_swap32(x)	bswap_32(x)
#define fio_swap64(x)	bswap_64(x)
#endif /* fio_swapN */

#define CACHE_LINE_FILE	\
	"/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size"

static inline int arch_cache_line_size(void)
{
	char size[32];
	int fd, ret;

	fd = open(CACHE_LINE_FILE, O_RDONLY);
	if (fd < 0)
		return -1;

	ret = read(fd, size, sizeof(size));

	close(fd);

	if (ret <= 0)
		return -1;
	else
		return atoi(size);
}

static inline unsigned long long get_fs_free_size(const char *path)
{
	unsigned long long ret;
	struct statfs s;

	if (statfs(path, &s) < 0)
		return -1ULL;

	ret = s.f_bsize;
	ret *= (unsigned long long) s.f_bfree;
	return ret;
}

static inline int os_trim(struct fio_file *f, unsigned long long start,
			  unsigned long long len)
{
	uint64_t range[2];

	range[0] = start;
	range[1] = len;

	if (!ioctl(f->fd, BLKDISCARD, range))
		return 0;

	return errno;
}

#ifdef CONFIG_SCHED_IDLE
static inline int fio_set_sched_idle(void)
{
        struct sched_param p = { .sched_priority = 0, };
        return sched_setscheduler(gettid(), SCHED_IDLE, &p);
}
#endif

#endif
