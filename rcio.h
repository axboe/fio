/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2026 Sandisk Corporation or its affiliates.
 */

#ifndef FIO_RCIO_H
#define FIO_RCIO_H

#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>

#include "flist.h"

struct frand_state;
struct thread_data;

/**
 * struct shared_rcio_entry - dual-list region tracker for region-constrained I/O
 *
 * Two logical lists backed by a single partitioned array.
 * regions[0 .. valid_count-1] hold written ("valid") region indices;
 * regions[valid_count .. num_regions-1] hold free ("invalid") region indices.
 *
 * State transitions happen at pick time (not at I/O completion).  A reverse
 * index maps each region number to its position in the partitioned array,
 * keeping completion-time state updates O(1).
 *
 * @filename:     file this entry belongs to; the lookup key is
 *                (filename, file_offset, region_size, num_regions), so
 *                entries with different geometry or range do not share state
 * @region_size:  bytes per region (= rcio_bs)
 * @num_regions:  total number of regions (N)
 * @regions:      partitioned array of all region indices
 * @region_pos:   reverse index from region number to its array position
 * @valid_count:  number of valid (written) regions = partition point
 * @mutex:        protects all mutable fields
 * @list:         linked into global shared_rcio_list
 */
struct shared_rcio_entry {
	char *filename;
	uint64_t file_offset;
	uint64_t region_size;
	uint64_t num_regions;

	uint32_t *regions;
	uint32_t *region_pos;
	uint64_t valid_count;

	pthread_mutex_t mutex;
	struct flist_head list;
};

/*
 * Allocate or look up a shared RCIO entry for the given file.
 * All regions start in the invalid (free) list.
 */
struct shared_rcio_entry *
get_shared_rcio(const char *filename, uint64_t file_offset,
		uint64_t region_size, uint64_t num_regions);

/*
 * Free all shared RCIO entries (called once at program exit).
 */
void free_all_shared_rcio(void);

/*
 * Pick a random region suitable for @ddir and update state atomically.
 *
 *   DDIR_WRITE  -> pick random invalid region, move it to valid   (O(1))
 *   DDIR_TRIM   -> pick random valid region,   move it to invalid (O(1))
 *   DDIR_READ   -> pick random valid region,   no state change    (O(1))
 *
 * Returns the region index, or (uint64_t)-1 if the applicable list is empty.
 */
uint64_t rcio_pick_region(struct shared_rcio_entry *entry,
			  int ddir, struct frand_state *rs);

/*
 * Update region state after sequential I/O completion.
 *
 *   DDIR_WRITE  -> mark covered regions as valid
 *   DDIR_TRIM   -> mark covered regions as invalid
 *
 * Uses a fast-path check at the partition boundary (O(1) for ordered
 * sequential writes during preconditioning), with scan fallback.
 */
void rcio_mark_region(struct shared_rcio_entry *entry,
		      uint64_t offset, uint64_t buflen, int ddir);

/*
 * Set up RCIO region tracking for all files of the job.  Returns true on
 * success, false on configuration error.
 */
bool init_rcio(struct thread_data *td);

#endif
