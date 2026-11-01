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
 * struct shared_rcio_entry - region tracker for region-constrained I/O
 *
 * Three logical lists backed by a single partitioned array.
 * regions[0 .. valid_count-1] hold available written ("valid") regions.
 * regions[valid_count .. num_regions-busy_count-1] hold available free
 * ("invalid") regions.
 * regions[num_regions-busy_count .. num_regions-1] hold reserved regions.
 *
 * A reverse index maps each region number to its position in the partitioned
 * array. Swaps move regions between partitions in O(1); reserved regions
 * cannot be selected until their I/O runs complete and release them.
 *
 * @filename:     file this entry belongs to; the lookup key is
 *                (filename, file_offset, region_size, num_regions), so
 *                entries with different geometry or range do not share state
 * @region_size:  bytes per region (= rcio_size)
 * @num_regions:  total number of regions (N)
 * @regions:      partitioned array of all region indices
 * @region_pos:   reverse index from region number to its array position
 * @region_pending: I/Os still owed by each reserved region, including I/Os
 *                 not yet issued
 * @valid_count:  number of available written regions = partition point
 * @busy_count:   number of regions reserved for in-flight I/O
 * @failed:       device state is uncertain; reject further selections
 * @mutex:        protects all mutable fields
 * @list:         linked into the shared tracker registry
 */
struct shared_rcio_entry {
	char *filename;
	uint64_t file_offset;
	uint64_t region_size;
	uint64_t num_regions;

	uint32_t *regions;
	uint32_t *region_pos;
	uint32_t *region_pending;
	uint64_t valid_count;
	uint64_t busy_count;
	bool failed;

	char *state_file;
	bool load_attempted;
	bool load_succeeded;
	bool load_failed;
	bool in_use;
	bool save_failed;

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
 * Save state and free all shared RCIO entries (called once at program exit).
 * @save must be false after backend errors or interruption.
 * Returns nonzero if any snapshot was withheld or could not be saved.
 */
int free_all_shared_rcio(bool save);

/* Record the outcome before the job's files are freed. */
void rcio_finish_job(struct thread_data *td, bool completed);
/* Retries or unissued sub-blocks remain in the current write/trim region. */
bool rcio_run_pending(struct thread_data *td);

/*
 * Pick and reserve a random region suitable for @ddir.
 *
 * @nr_ios is the number of I/Os in the run and must be nonzero. The region
 * remains reserved until they complete. Returns RCIO_REGION_BUSY if a
 * reservation may become available, RCIO_REGION_FAILED if the tracker has
 * failed, or UINT64_MAX if the applicable list is empty and no reservations
 * remain.
 */
#define RCIO_REGION_BUSY (UINT64_MAX - 1)
#define RCIO_REGION_FAILED (UINT64_MAX - 2)

uint64_t rcio_pick_region(struct shared_rcio_entry *entry,
			  int ddir, struct frand_state *rs, uint32_t nr_ios);

/*
 * Account for completed I/Os in a reserved region. For reads, @nr_ios may
 * also include unissued I/Os when an incomplete run is closed. Release the
 * region when no I/Os remain.
 *
 * @ddir must match the direction used to reserve the region. Writes become
 * valid, trims become invalid, and reads remain valid.
 * Failed I/Os must not be counted; call rcio_fail() instead.
 * Returns zero on success or a negative error for invalid accounting.
 */
int rcio_complete_region(struct shared_rcio_entry *entry, uint64_t region,
			 int ddir, uint32_t nr_ios);

/* Prevent further selections after an I/O failure leaves state uncertain. */
void rcio_fail(struct shared_rcio_entry *entry);

/*
 * Update region state after sequential I/O completion.
 *
 *   DDIR_WRITE  -> mark covered regions as valid
 *   DDIR_TRIM   -> mark covered regions as invalid
 *
 * Returns -EBUSY if a covered region is reserved.
 */
int rcio_mark_region(struct shared_rcio_entry *entry,
		     uint64_t offset, uint64_t buflen, int ddir);

/*
 * Set up RCIO region tracking for all files of the job.  Returns 0 on
 * success, 1 on setup failure.
 */
int init_rcio(struct thread_data *td);

/* Initialize the shared registry in the parent before any jobs are forked. */
int init_shared_rcio(void);

#endif
