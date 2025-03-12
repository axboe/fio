#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <stdio.h>

#include "helpers.h"

#ifndef CONFIG_LINUX_FALLOCATE
int fallocate(int fd, int mode, off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}
#endif

#ifndef CONFIG_POSIX_FALLOCATE
int posix_fallocate(int fd, off_t offset, off_t len)
{
	return 0;
}
#endif

#ifndef CONFIG_SYNC_FILE_RANGE
int sync_file_range(int fd, uint64_t offset, uint64_t nbytes,
		    unsigned int flags)
{
	errno = ENOSYS;
	return -1;
}
#endif

#ifdef CONFIG_MAC_FADVISE_DISCARD
/**
 * CONFIG_MAC_FADVISE_DISCARD should not be run within Rosetta. Native arm64 or x86 only.
 */

#define MMAP_CHUNK_SIZE		(1024 * 1024 * 1024)

int discard_pages(int fd, off_t offset, off_t size)
{
	caddr_t *addr;
	uint64_t chunk_size = MMAP_CHUNK_SIZE;

	printf("fsync'ing file, then invalidating UBC.\n");
	if (fsync(fd) < 0) {
		fprintf(stderr, "Cannot fsync file\n");
		exit(1);
	}

	/*
	 * mmap the file in 1GB chunks and msync(MS_INVALIDATE).
	 */
	while (size > 0) {
		uint64_t mmap_size = MIN(chunk_size, size);

		addr = mmap((caddr_t)0, mmap_size, PROT_NONE, MAP_SHARED, fd, offset);
		if (addr == MAP_FAILED) {
			fprintf(stderr, "Failed to mmap (%s), offset = %llu, size = %llu\n",
				strerror(errno), offset, mmap_size);
			return -1;
		}

		if (msync(addr, mmap_size, MS_INVALIDATE)) {
			fprintf(stderr, "msync failed to free cache pages.\n");
			return -1;
		}

		/* Destroy the above mappings used to invalidate cache - cleaning up */
		if (munmap(addr, mmap_size) < 0) {
			fprintf(stderr, "munmap failed, error = %d.\n", errno);
			return -1;
		}

		size -= mmap_size;
		offset += mmap_size;
	}

	return 0;
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	int ret = 0;

	if (advice == POSIX_FADV_DONTNEED)
		ret = discard_pages(fd, offset, len);
	return ret;
}
#else
#ifndef CONFIG_POSIX_FADVISE
int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	return 0;
}
#endif
#endif //CONFIG_MAC_FADVISE_DISCARD
