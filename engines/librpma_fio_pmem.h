/*
 * librpma_fio_pmem: allocates pmem using libpmem.
 *
 * Copyright 2022, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#include <libpmem.h>
#include "librpma_fio.h"

#define RPMA_PMEM_USED "libpmem"

static int librpma_fio_pmem_map_file(struct fio_file *f, size_t size,
		struct librpma_fio_mem *mem, size_t ws_offset)
{
	int is_pmem = 0;
	size_t size_mmap = 0;

	/* map the file */
	mem->mem_ptr = pmem_map_file(f->file_name, 0 /* len */, 0 /* flags */,
			0 /* mode */, &size_mmap, &is_pmem);
	if (mem->mem_ptr == NULL) {
		/* pmem_map_file() sets errno on failure */
		log_err("fio: pmem_map_file(%s) failed: %s (errno %i)\n",
			f->file_name, strerror(errno), errno);
		return -1;
	}

	/* pmem is expected */
	if (!is_pmem) {
		log_err("fio: %s is not located in persistent memory\n",
			f->file_name);
		goto err_unmap;
	}

	/* check size of allocated persistent memory */
	if (size_mmap < ws_offset + size) {
		log_err(
			"fio: %s is too small to handle so many threads (%zu < %zu)\n",
			f->file_name, size_mmap, ws_offset + size);
		goto err_unmap;
	}

	log_info("fio: size of memory mapped from the file %s: %zu\n",
		f->file_name, size_mmap);

	mem->size_mmap = size_mmap;

	return 0;

err_unmap:
	(void) pmem_unmap(mem->mem_ptr, size_mmap);
	return -1;
}

static inline void librpma_fio_unmap(struct librpma_fio_mem *mem)
{
	(void) pmem_unmap(mem->mem_ptr, mem->size_mmap);
}
