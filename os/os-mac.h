#ifndef FIO_OS_APPLE_H
#define FIO_OS_APPLE_H

#define	FIO_OS	os_mac

#include <errno.h>
#include <fcntl.h>
#include <sys/disk.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <mach/mach_init.h>
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>


#include "../arch/arch.h"
#include "../file.h"
#include "../log.h"

#define FIO_USE_GENERIC_INIT_RANDOM_STATE
#define FIO_HAVE_GETTID
#define FIO_HAVE_CHARDEV_SIZE
#define FIO_HAVE_NATIVE_FALLOCATE
#define FIO_HAVE_CPU_HAS

#define OS_MAP_ANON		MAP_ANON

#define fio_swap16(x)	OSSwapInt16(x)
#define fio_swap32(x)	OSSwapInt32(x)
#define fio_swap64(x)	OSSwapInt64(x)

#ifdef CONFIG_PTHREAD_GETAFFINITY
#define FIO_HAVE_GET_THREAD_AFFINITY
#define fio_get_thread_affinity(mask)	\
	pthread_getaffinity_np(pthread_self(), sizeof(mask), &(mask))
#endif

#ifndef CONFIG_CLOCKID_T
typedef unsigned int clockid_t;
#endif

#define FIO_OS_DIRECTIO
static inline int fio_set_odirect(struct fio_file *f)
{
	if (fcntl(f->fd, F_NOCACHE, 1) == -1)
		return errno;
	return 0;
}

static inline int blockdev_size(struct fio_file *f, unsigned long long *bytes)
{
	uint32_t block_size;
	uint64_t block_count;

	if (ioctl(f->fd, DKIOCGETBLOCKCOUNT, &block_count) == -1)
		return errno;
	if (ioctl(f->fd, DKIOCGETBLOCKSIZE, &block_size) == -1)
		return errno;

	*bytes = block_size;
	*bytes *= block_count;
	return 0;
}

static inline int chardev_size(struct fio_file *f, unsigned long long *bytes)
{
	/*
	 * Could be a raw block device, this is better than just assuming
	 * we can't get the size at all.
	 */
	if (!blockdev_size(f, bytes))
		return 0;

	*bytes = -1ULL;
	return 0;
}

static inline int blockdev_invalidate_cache(struct fio_file *f)
{
	return ENOTSUP;
}

static inline unsigned long long os_phys_mem(void)
{
	int mib[2] = { CTL_HW, HW_PHYSMEM };
	unsigned long long mem;
	size_t len = sizeof(mem);

	sysctl(mib, 2, &mem, &len, NULL, 0);
	return mem;
}

#ifndef CONFIG_HAVE_GETTID
static inline int gettid(void)
{
	return mach_thread_self();
}
#endif

static inline bool fio_fallocate(struct fio_file *f, uint64_t offset, uint64_t len)
{
	fstore_t store = {F_ALLOCATEALL, F_PEOFPOSMODE, offset, len};
	if (fcntl(f->fd, F_PREALLOCATE, &store) != -1) {
		if (ftruncate(f->fd, len) == 0)
			return true;
	}

	return false;
}

static inline bool os_cpu_has(cpu_features feature)
{
	/* just check for arm on OSX for now, we know that has it */
	if (feature != CPU_ARM64_CRC32C)
		return false;
	return FIO_ARCH == arch_aarch64;
}

#endif

/*
 * discard_pages should not be run within Rosetta. Native arm64 or x86 only. 
 */

#define MMAP_CHUNK_SIZE		(1024 * 1024 * 1024)

static inline int discard_pages(int fd, off_t offset, off_t size)
{
	caddr_t *addr;
	uint64_t chunk_size = MMAP_CHUNK_SIZE;

	if (fsync(fd) < 0) {
                int __err = errno; 
		log_err("%s: Cannot fsync file: %s \n", __func__, strerror(errno));
                errno = __err;
		return -1;
	}	    
    
	/*
	 * mmap the file in 1GB chunks and msync(MS_INVALIDATE).
	 */
	while (size > 0) {
		uint64_t mmap_size = MIN(chunk_size, size);

		addr = mmap((caddr_t)0, mmap_size, PROT_NONE, MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED) {
                        int __map_errno = errno;
			fprintf(stderr, "Failed to mmap (%s), offset = %llu, size = %llu\n",
				strerror(errno), offset, mmap_size);
                        errno = __map_errno;
			return -1;
		}

		if (msync(addr, mmap_size, MS_INVALIDATE)) {
                        int __msync_errno = errno;
			fprintf(stderr, "msync failed to free cache pages.\n");
                        errno = __msync_errno;
			return -1;
		}

		/* Destroy the above mappings used to invalidate cache - cleaning up */
		if (munmap(addr, mmap_size) < 0) {
                        int __munmap_errno = errno;
			fprintf(stderr, "munmap failed, error = %d.\n", errno);
                        errno = __munmap_errno;
			return -1;
		}

		size -= mmap_size;
		offset += mmap_size;
	}

	return 0;
}
