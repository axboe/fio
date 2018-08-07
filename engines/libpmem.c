/*
 * libpmem: IO engine that uses PMDK libpmem to read and write data
 *
 * Copyright (C) 2017 Nippon Telegraph and Telephone Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 */

/*
 * libpmem engine
 *
 * IO engine that uses libpmem to read and write data
 *
 * To use:
 *   ioengine=libpmem
 *
 * Other relevant settings:
 *   iodepth=1
 *   direct=1
 *   directory=/mnt/pmem0/
 *   bs=4k
 *
 *   direct=1 means that pmem_drain() is executed for each write operation.
 *   In contrast, direct=0 means that pmem_drain() is not executed.
 *
 *   The pmem device must have a DAX-capable filesystem and be mounted
 *   with DAX enabled. directory must point to a mount point of DAX FS.
 *
 *   Example:
 *     mkfs.xfs /dev/pmem0
 *     mkdir /mnt/pmem0
 *     mount -o dax /dev/pmem0 /mnt/pmem0
 *
 *
 * See examples/libpmem.fio for more.
 *
 *
 * libpmem.so
 *   By default, the libpmem engine will let the system find the libpmem.so
 *   that it uses. You can use an alternative libpmem by setting the
 *   FIO_PMEM_LIB environment variable to the full path to the desired
 *   libpmem.so.
 */

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <libgen.h>
#include <libpmem.h>

#include "../fio.h"
#include "../verify.h"

/*
 * Limits us to 1GiB of mapped files in total to model after
 * libpmem engine behavior
 */
#define MMAP_TOTAL_SZ   (1 * 1024 * 1024 * 1024UL)

struct fio_libpmem_data {
	void *libpmem_ptr;
	size_t libpmem_sz;
	off_t libpmem_off;
};

#define MEGABYTE ((uintptr_t)1 << 20)
#define GIGABYTE ((uintptr_t)1 << 30)
#define PROCMAXLEN 2048 /* maximum expected line length in /proc files */
#define roundup(x, y)   ((((x) + ((y) - 1)) / (y)) * (y))

static bool Mmap_no_random;
static void *Mmap_hint;
static unsigned long long Mmap_align;

/*
 * util_map_hint_align -- choose the desired mapping alignment
 *
 * Use 2MB/1GB page alignment only if the mapping length is at least
 * twice as big as the page size.
 */
static inline size_t util_map_hint_align(size_t len, size_t req_align)
{
	size_t align = Mmap_align;

	dprint(FD_IO, "DEBUG util_map_hint_align\n" );

	if (req_align)
		align = req_align;
	else if (len >= 2 * GIGABYTE)
		align = GIGABYTE;
	else if (len >= 4 * MEGABYTE)
		align = 2 * MEGABYTE;

	dprint(FD_IO, "align=%d\n", (int)align);
	return align;
}

#ifdef __FreeBSD__
static const char *sscanf_os = "%p %p";
#define MAP_NORESERVE 0
#define OS_MAPFILE "/proc/curproc/map"
#else
static const char *sscanf_os = "%p-%p";
#define OS_MAPFILE "/proc/self/maps"
#endif

/*
 * util_map_hint_unused -- use /proc to determine a hint address for mmap()
 *
 * This is a helper function for util_map_hint().
 * It opens up /proc/self/maps and looks for the first unused address
 * in the process address space that is:
 * - greater or equal 'minaddr' argument,
 * - large enough to hold range of given length,
 * - aligned to the specified unit.
 *
 * Asking for aligned address like this will allow the DAX code to use large
 * mappings.  It is not an error if mmap() ignores the hint and chooses
 * different address.
 */
static char *util_map_hint_unused(void *minaddr, size_t len, size_t align)
{
	char *lo = NULL;        /* beginning of current range in maps file */
	char *hi = NULL;        /* end of current range in maps file */
	char *raddr = minaddr;  /* ignore regions below 'minaddr' */

#ifdef WIN32
	MEMORY_BASIC_INFORMATION mi;
#else
	FILE *fp;
	char line[PROCMAXLEN];  /* for fgets() */
#endif

	dprint(FD_IO, "DEBUG util_map_hint_unused\n");
	assert(align > 0);

	if (raddr == NULL)
		raddr += page_size;

	raddr = (char *)roundup((uintptr_t)raddr, align);

#ifdef WIN32
	while ((uintptr_t)raddr < UINTPTR_MAX - len) {
		size_t ret = VirtualQuery(raddr, &mi, sizeof(mi));
		if (ret == 0) {
			ERR("VirtualQuery %p", raddr);
			return MAP_FAILED;
		}
		dprint(FD_IO, "addr %p len %zu state %d",
				mi.BaseAddress, mi.RegionSize, mi.State);

		if ((mi.State != MEM_FREE) || (mi.RegionSize < len)) {
			raddr = (char *)mi.BaseAddress + mi.RegionSize;
			raddr = (char *)roundup((uintptr_t)raddr, align);
			dprint(FD_IO, "nearest aligned addr %p", raddr);
		} else {
			dprint(FD_IO, "unused region of size %zu found at %p",
					mi.RegionSize, mi.BaseAddress);
			return mi.BaseAddress;
		}
	}

	dprint(FD_IO, "end of address space reached");
	return MAP_FAILED;
#else
	fp = fopen(OS_MAPFILE, "r");
	if (!fp) {
		log_err("!%s\n", OS_MAPFILE);
		return MAP_FAILED;
	}

	while (fgets(line, PROCMAXLEN, fp) != NULL) {
		/* check for range line */
		if (sscanf(line, sscanf_os, &lo, &hi) == 2) {
			dprint(FD_IO, "%p-%p\n", lo, hi);
			if (lo > raddr) {
				if ((uintptr_t)(lo - raddr) >= len) {
					dprint(FD_IO, "unused region of size "
							"%zu found at %p\n",
							lo - raddr, raddr);
					break;
				} else {
					dprint(FD_IO, "region is too small: "
							"%zu < %zu\n",
							lo - raddr, len);
				}
			}

			if (hi > raddr) {
				raddr = (char *)roundup((uintptr_t)hi, align);
				dprint(FD_IO, "nearest aligned addr %p\n",
						raddr);
			}

			if (raddr == 0) {
				dprint(FD_IO, "end of address space reached\n");
				break;
			}
		}
	}

	/*
	 * Check for a case when this is the last unused range in the address
	 * space, but is not large enough. (very unlikely)
	 */
	if ((raddr != NULL) && (UINTPTR_MAX - (uintptr_t)raddr < len)) {
		dprint(FD_IO, "end of address space reached");
		raddr = MAP_FAILED;
	}

	fclose(fp);

	dprint(FD_IO, "returning %p", raddr);
	return raddr;
#endif
}

/*
 * util_map_hint -- determine hint address for mmap()
 *
 * If PMEM_MMAP_HINT environment variable is not set, we let the system to pick
 * the randomized mapping address.  Otherwise, a user-defined hint address
 * is used.
 *
 * Windows Environment:
 *   XXX - Windows doesn't support large DAX pages yet, so there is
 *   no point in aligning for the same.
 *
 * Except for Windows Environment:
 *   ALSR in 64-bit Linux kernel uses 28-bit of randomness for mmap
 *   (bit positions 12-39), which means the base mapping address is randomized
 *   within [0..1024GB] range, with 4KB granularity.  Assuming additional
 *   1GB alignment, it results in 1024 possible locations.
 *
 *   Configuring the hint address via PMEM_MMAP_HINT environment variable
 *   disables address randomization.  In such case, the function will search for
 *   the first unused, properly aligned region of given size, above the
 *   specified address.
 */
static char *util_map_hint(size_t len, size_t req_align)
{
	char *addr;
	size_t align = 0;
	char *e = NULL;

	dprint(FD_IO, "DEBUG util_map_hint\n");
	dprint(FD_IO, "len %zu req_align %zu\n", len, req_align);

	/* choose the desired alignment based on the requested length */
	align = util_map_hint_align(len, req_align);

	e = getenv("PMEM_MMAP_HINT");
	if (e) {
		char *endp;
		unsigned long long val = 0;

		errno = 0;

		val = strtoull(e, &endp, 16);
		if (errno || endp == e) {
			dprint(FD_IO, "Invalid PMEM_MMAP_HINT\n");
		} else {
			Mmap_hint = (void *)val;
			Mmap_no_random = true;
			dprint(FD_IO, "PMEM_MMAP_HINT set to %p\n", Mmap_hint);
		}
	}

	if (Mmap_no_random) {
		dprint(FD_IO, "user-defined hint %p\n", (void *)Mmap_hint);
		addr = util_map_hint_unused((void *)Mmap_hint, len, align);
	} else {
		/*
		 * Create dummy mapping to find an unused region of given size.
		 * * Request for increased size for later address alignment.
		 *
		 * Windows Environment: 
		 *   Use MAP_NORESERVE flag to only reserve the range of pages
		 *   rather than commit.  We don't want the pages to be actually
		 *   backed by the operating system paging file, as the swap
		 *   file is usually too small to handle terabyte pools.
		 *
		 * Except for Windows Environment:
		 *   Use MAP_PRIVATE with read-only access to simulate
		 *   zero cost for overcommit accounting.  Note: MAP_NORESERVE
		 *   flag is ignored if overcommit is disabled (mode 2).
		 */
#ifndef WIN32
		addr = mmap(NULL, len + align, PROT_READ,
				MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
#else
		addr = mmap(NULL, len + align, PROT_READ,
				MAP_PRIVATE|MAP_ANONYMOUS|MAP_NORESERVE, -1, 0);
#endif
		if (addr != MAP_FAILED) {
			dprint(FD_IO, "system choice %p\n", addr);
			munmap(addr, len + align);
			addr = (char *)roundup((uintptr_t)addr, align);
		}
	}

	dprint(FD_IO, "hint %p\n", addr);

	return addr;
}

/*
 * This is the mmap execution function
 */
static int fio_libpmem_file(struct thread_data *td, struct fio_file *f,
			    size_t length, off_t off)
{
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);
	int flags = 0;
	void *addr = NULL;

	dprint(FD_IO, "DEBUG fio_libpmem_file\n");

	if (td_rw(td))
		flags = PROT_READ | PROT_WRITE;
	else if (td_write(td)) {
		flags = PROT_WRITE;

		if (td->o.verify != VERIFY_NONE)
			flags |= PROT_READ;
	} else
		flags = PROT_READ;

	dprint(FD_IO, "f->file_name = %s  td->o.verify = %d \n", f->file_name,
			td->o.verify);
	dprint(FD_IO, "length = %ld  flags = %d  f->fd = %d off = %ld \n",
			length, flags, f->fd,off);

	addr = util_map_hint(length, 0);

	fdd->libpmem_ptr = mmap(addr, length, flags, MAP_SHARED, f->fd, off);
	if (fdd->libpmem_ptr == MAP_FAILED) {
		fdd->libpmem_ptr = NULL;
		td_verror(td, errno, "mmap");
	}

	if (td->error && fdd->libpmem_ptr)
		munmap(fdd->libpmem_ptr, length);

	return td->error;
}

/*
 * XXX Just mmap an appropriate portion, we cannot mmap the full extent
 */
static int fio_libpmem_prep_limited(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);

	dprint(FD_IO, "DEBUG fio_libpmem_prep_limited\n" );

	if (io_u->buflen > f->real_file_size) {
		log_err("libpmem: bs too big for libpmem engine\n");
		return EIO;
	}

	fdd->libpmem_sz = min(MMAP_TOTAL_SZ, f->real_file_size);
	if (fdd->libpmem_sz > f->io_size)
		fdd->libpmem_sz = f->io_size;

	fdd->libpmem_off = io_u->offset;

	return fio_libpmem_file(td, f, fdd->libpmem_sz, fdd->libpmem_off);
}

/*
 * Attempt to mmap the entire file
 */
static int fio_libpmem_prep_full(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);
	int ret;

	dprint(FD_IO, "DEBUG fio_libpmem_prep_full\n" );

	if (fio_file_partial_mmap(f))
		return EINVAL;

	dprint(FD_IO," f->io_size %ld : io_u->offset %lld \n",
			f->io_size, io_u->offset);

	if (io_u->offset != (size_t) io_u->offset ||
	    f->io_size != (size_t) f->io_size) {
		fio_file_set_partial_mmap(f);
		return EINVAL;
	}
	fdd->libpmem_sz = f->io_size;
	fdd->libpmem_off = 0;

	ret = fio_libpmem_file(td, f, fdd->libpmem_sz, fdd->libpmem_off);
	if (ret)
		fio_file_set_partial_mmap(f);

	return ret;
}

static int fio_libpmem_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);
	int ret;

	dprint(FD_IO, "DEBUG fio_libpmem_prep\n" );
	/*
	 * It fits within existing mapping, use it
	 */
	dprint(FD_IO," io_u->offset %llu : fdd->libpmem_off %llu : "
			"io_u->buflen %llu : fdd->libpmem_sz %llu\n",
			io_u->offset, (unsigned long long) fdd->libpmem_off,
			io_u->buflen, (unsigned long long) fdd->libpmem_sz);

	if (io_u->offset >= fdd->libpmem_off &&
	    (io_u->offset + io_u->buflen <=
	     fdd->libpmem_off + fdd->libpmem_sz))
		goto done;

	/*
	 * unmap any existing mapping
	 */
	if (fdd->libpmem_ptr) {
		dprint(FD_IO,"munmap \n");
		if (munmap(fdd->libpmem_ptr, fdd->libpmem_sz) < 0)
			return errno;
		fdd->libpmem_ptr = NULL;
	}

	if (fio_libpmem_prep_full(td, io_u)) {
		td_clear_error(td);
		ret = fio_libpmem_prep_limited(td, io_u);
		if (ret)
			return ret;
	}

done:
	io_u->mmap_data = fdd->libpmem_ptr + io_u->offset - fdd->libpmem_off
				- f->file_offset;
	return 0;
}

static enum fio_q_status fio_libpmem_queue(struct thread_data *td,
					   struct io_u *io_u)
{
	fio_ro_check(td, io_u);
	io_u->error = 0;

	dprint(FD_IO, "DEBUG fio_libpmem_queue\n");

	switch (io_u->ddir) {
	case DDIR_READ:
		memcpy(io_u->xfer_buf, io_u->mmap_data, io_u->xfer_buflen);
		break;
	case DDIR_WRITE:
		dprint(FD_IO, "DEBUG mmap_data=%p, xfer_buf=%p\n",
				io_u->mmap_data, io_u->xfer_buf );
		dprint(FD_IO,"td->o.odirect %d \n",td->o.odirect);
		if (td->o.odirect) {
			pmem_memcpy_persist(io_u->mmap_data,
						io_u->xfer_buf,
						io_u->xfer_buflen);
		} else {
			pmem_memcpy_nodrain(io_u->mmap_data,
						io_u->xfer_buf,
						io_u->xfer_buflen);
		}
		break;
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
		break;
	default:
		io_u->error = EINVAL;
		break;
	}

	return FIO_Q_COMPLETED;
}

static int fio_libpmem_init(struct thread_data *td)
{
	struct thread_options *o = &td->o;

	dprint(FD_IO,"o->rw_min_bs %llu \n o->fsync_blocks %d \n o->fdatasync_blocks %d \n",
			o->rw_min_bs,o->fsync_blocks,o->fdatasync_blocks);
	dprint(FD_IO, "DEBUG fio_libpmem_init\n");

	if ((o->rw_min_bs & page_mask) &&
	    (o->fsync_blocks || o->fdatasync_blocks)) {
		log_err("libpmem: mmap options dictate a minimum block size of "
				"%llu bytes\n",	(unsigned long long) page_size);
		return 1;
	}
	return 0;
}

static int fio_libpmem_open_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_libpmem_data *fdd;
	int ret;

	dprint(FD_IO,"DEBUG fio_libpmem_open_file\n");
	dprint(FD_IO,"f->io_size=%ld \n",f->io_size);
	dprint(FD_IO,"td->o.size=%lld \n",td->o.size);
	dprint(FD_IO,"td->o.iodepth=%d\n",td->o.iodepth);
	dprint(FD_IO,"td->o.iodepth_batch=%d \n",td->o.iodepth_batch);

	ret = generic_open_file(td, f);
	if (ret)
		return ret;

	fdd = calloc(1, sizeof(*fdd));
	if (!fdd) {
		int fio_unused __ret;
		__ret = generic_close_file(td, f);
		return 1;
	}

	FILE_SET_ENG_DATA(f, fdd);

	return 0;
}

static int fio_libpmem_close_file(struct thread_data *td, struct fio_file *f)
{
	struct fio_libpmem_data *fdd = FILE_ENG_DATA(f);

	dprint(FD_IO,"DEBUG fio_libpmem_close_file\n");
	dprint(FD_IO,"td->o.odirect %d \n",td->o.odirect);

	if (!td->o.odirect) {
		dprint(FD_IO,"pmem_drain\n");
		pmem_drain();
	}

	FILE_SET_ENG_DATA(f, NULL);
	free(fdd);
	fio_file_clear_partial_mmap(f);

	return generic_close_file(td, f);
}

static struct ioengine_ops ioengine = {
	.name		= "libpmem",
	.version	= FIO_IOOPS_VERSION,
	.init		= fio_libpmem_init,
	.prep		= fio_libpmem_prep,
	.queue		= fio_libpmem_queue,
	.open_file	= fio_libpmem_open_file,
	.close_file	= fio_libpmem_close_file,
	.get_file_size	= generic_get_file_size,
	.flags		= FIO_SYNCIO |FIO_NOEXTEND,
};

static void fio_init fio_libpmem_register(void)
{
#ifndef WIN32
	Mmap_align = page_size;
#else
	if (Mmap_align == 0) {
		SYSTEM_INFO si;

		GetSystemInfo(&si);
		Mmap_align = si.dwAllocationGranularity;
	}
#endif

	register_ioengine(&ioengine);
}

static void fio_exit fio_libpmem_unregister(void)
{
	unregister_ioengine(&ioengine);
}
