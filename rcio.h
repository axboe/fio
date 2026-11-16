/**
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2026 Sandisk Corporation or its affiliates.
 */

#ifndef FIO_RCIO_H
#define FIO_RCIO_H

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>

#include "flist.h"

struct frand_state;

#define RCIO_REGION_RESERVED	(UINT64_MAX - 1)
#define RCIO_REGION_FAILED	(UINT64_MAX - 2)

struct shared_rcio_entry {
	char *filename;
	uint64_t file_offset;
	uint64_t region_size;
	uint64_t num_regions;

	/* Valid, free and reserved partitions, in that order. */
	uint32_t *regions;
	uint32_t *region_pos;
	int *region_ddir;
	uint64_t valid_count;
	uint64_t reserved_count;
	bool failed;

	pthread_mutex_t mutex;
	struct flist_head list;
};

int init_shared_rcio(void);
int free_all_shared_rcio(void);

struct shared_rcio_entry *
get_shared_rcio(const char *filename, uint64_t file_offset,
		uint64_t region_size, uint64_t num_regions);

uint64_t rcio_pick_region(struct shared_rcio_entry *entry, int ddir,
			  struct frand_state *rs);
int rcio_complete_region(struct shared_rcio_entry *entry, uint64_t region,
			 int ddir);
void rcio_fail(struct shared_rcio_entry *entry);

#endif
