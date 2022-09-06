/*
 * librpma_fio_pmem2: allocates pmem using libpmem2.
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

#include <libpmem2.h>
#include "librpma_fio.h"

#define RPMA_PMEM_USED "libpmem2"

static int librpma_fio_pmem_map_file(struct fio_file *f, size_t size,
		struct librpma_fio_mem *mem, size_t ws_offset)
{
	int fd;
	struct pmem2_config *cfg = NULL;
	struct pmem2_map *map = NULL;
	struct pmem2_source *src = NULL;

	size_t size_mmap;

	if((fd = open(f->file_name, O_RDWR)) < 0) {
		log_err("fio: cannot open fio file\n");
		return -1;
	}

	if (pmem2_source_from_fd(&src, fd) != 0) {
		log_err("fio: pmem2_source_from_fd() failed\n");
		goto err_close;
	}

	if (pmem2_config_new(&cfg) != 0) {
		log_err("fio: pmem2_config_new() failed\n");
		goto err_source_delete;
	}

	if (pmem2_config_set_required_store_granularity(cfg,
					PMEM2_GRANULARITY_CACHE_LINE) != 0) {
		log_err("fio: pmem2_config_set_required_store_granularity() failed: %s\n", pmem2_errormsg());
		goto err_config_delete;
	}

	if (pmem2_map_new(&map, cfg, src) != 0) {
		log_err("fio: pmem2_map_new(%s) failed: %s\n", f->file_name, pmem2_errormsg());
		goto err_config_delete;
	}

	size_mmap = pmem2_map_get_size(map);

	/* check size of allocated persistent memory */
	if (size_mmap < ws_offset + size) {
		log_err(
			"fio: %s is too small to handle so many threads (%zu < %zu)\n",
			f->file_name, size_mmap, ws_offset + size);
		goto err_map_delete;
	}

	mem->mem_ptr = pmem2_map_get_address(map);
	mem->size_mmap = size_mmap;
	mem->map = map;
	pmem2_config_delete(&cfg);
	pmem2_source_delete(&src);
	close(fd);

	return 0;

err_map_delete:
	pmem2_map_delete(&map);
err_config_delete:
	pmem2_config_delete(&cfg);
err_source_delete:
	pmem2_source_delete(&src);
err_close:
	close(fd);

	return -1;
}

static inline void librpma_fio_unmap(struct librpma_fio_mem *mem)
{
	(void) pmem2_map_delete(&mem->map);
}
