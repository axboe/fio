#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/param.h>

#include "../../log.h"

#include "posix.h"

#define MMAP_CHUNK_SIZE		(16LL * 1024 * 1024 * 1024)

/*
 * NB: performance of discard_pages() will be slower under Rosetta.
 */
static int discard_pages(int fd, off_t offset, off_t len)
{
	/* Align offset and len to page size */
	long pagesize = sysconf(_SC_PAGESIZE);
	long offset_pad = offset % pagesize;
	offset -= offset_pad;
	len += offset_pad;
	len = (len + pagesize - 1) & -pagesize;

	while (len > 0) {
		int saved_errno;
		size_t mmap_len = MIN(MMAP_CHUNK_SIZE, len);
		void *addr = mmap(0, mmap_len, PROT_NONE, MAP_SHARED, fd,
				  offset);

		if (addr == MAP_FAILED) {
			saved_errno = errno;
			log_err("discard_pages: failed to mmap (%s), "
				"offset = %llu, len = %zu\n",
				strerror(errno), offset, mmap_len);
			return saved_errno;
		}

		if (msync(addr, mmap_len, MS_INVALIDATE)) {
			saved_errno = errno;
			log_err("discard_pages: msync failed to free cache "
				"pages\n");

			if (munmap(addr, mmap_len) < 0)
				log_err("discard_pages: munmap failed (%s)\n",
					strerror(errno));
			return saved_errno;
		}

		if (munmap(addr, mmap_len) < 0) {
			saved_errno = errno;
			log_err("discard_pages: munmap failed (%s), "
				"len = %zu)\n", strerror(errno), mmap_len);
			return saved_errno;
		}

		len -= mmap_len;
		offset += mmap_len;
	}

	return 0;
}

static inline int set_readhead(int fd, bool enabled) {
	int ret;

	ret = fcntl(fd, F_RDAHEAD, enabled ? 1 : 0);
	if (ret == -1) {
		ret = errno;
	}

	return ret;
}

int posix_fadvise(int fd, off_t offset, off_t len, int advice)
{
	int ret;

	switch(advice) {
	case POSIX_FADV_NORMAL:
		ret = 0;
		break;
	case POSIX_FADV_RANDOM:
		ret = set_readhead(fd, false);
		break;
	case POSIX_FADV_SEQUENTIAL:
		ret = set_readhead(fd, true);
		break;
	case POSIX_FADV_DONTNEED:
		ret = discard_pages(fd, offset, len);
		break;
	default:
		ret = EINVAL;
	}

	return ret;
}
