/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2026 Sandisk Corporation or its affiliates.
 */

/*
 * Region-constrained I/O (RCIO) region tracker.
 *
 * Maintains a partitioned array of region indices shared across jobs.
 * See rcio.h for the data-structure description.
 */
#include "fio.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "rcio.h"
#include "flist.h"
#include "io_ddir.h"
#include "log.h"
#include "lib/rand.h"
#include "smalloc.h"
#include "pshared.h"

static struct {
	struct flist_head list;
	pthread_mutex_t mutex;
} *shared_rcio;

int init_shared_rcio(void)
{
	shared_rcio = scalloc(1, sizeof(*shared_rcio));
	if (!shared_rcio) {
		log_err("fio: failed to allocate shared RCIO registry\n");
		return 1;
	}
	INIT_FLIST_HEAD(&shared_rcio->list);
	if (mutex_init_pshared(&shared_rcio->mutex)) {
		sfree(shared_rcio);
		shared_rcio = NULL;
		return 1;
	}
	return 0;
}

/*
 * Find a tracker matching the file and region geometry, or return NULL.
 * Caller must hold shared_rcio->mutex.
 */
static struct shared_rcio_entry *
find_shared_rcio(const char *filename, uint64_t file_offset,
		 uint64_t region_size, uint64_t num_regions)
{
	struct flist_head *pos;
	struct shared_rcio_entry *entry;

	flist_for_each(pos, &shared_rcio->list) {
		entry = flist_entry(pos, struct shared_rcio_entry, list);
		if (!strcmp(entry->filename, filename) &&
		    entry->file_offset == file_offset &&
		    entry->region_size == region_size &&
		    entry->num_regions == num_regions)
			return entry;
	}
	return NULL;
}

/*
 * Check whether [file_offset, file_offset + region_size * num_regions)
 * overlaps the range of an existing tracker on the same file.  Two
 * independent trackers covering overlapping bytes would each believe they
 * exclusively own regions in the overlap, corrupting each other's view of
 * what is actually valid on device.  Caller must hold shared_rcio->mutex.
 */
static bool rcio_range_overlaps(const char *filename, uint64_t file_offset,
				uint64_t region_size, uint64_t num_regions)
{
	struct flist_head *pos;
	struct shared_rcio_entry *entry;
	uint64_t start = file_offset;
	uint64_t end = file_offset + region_size * num_regions;

	flist_for_each(pos, &shared_rcio->list) {
		uint64_t entry_start, entry_end;

		entry = flist_entry(pos, struct shared_rcio_entry, list);
		if (strcmp(entry->filename, filename))
			continue;

		entry_start = entry->file_offset;
		entry_end = entry->file_offset +
			    entry->region_size * entry->num_regions;

		if (start < entry_end && entry_start < end)
			return true;
	}

	return false;
}

/*
 * Reuse a tracker with matching file and geometry, or allocate an initially
 * empty one. Reject overlapping ranges with different geometry.
 * Returns NULL on conflicting ranges or allocation/initialization failure.
 */
struct shared_rcio_entry *
get_shared_rcio(const char *filename, uint64_t file_offset,
		uint64_t region_size, uint64_t num_regions)
{
	struct shared_rcio_entry *entry;
	uint64_t i;

	pthread_mutex_lock(&shared_rcio->mutex);

	entry = find_shared_rcio(filename, file_offset, region_size,
				 num_regions);
	if (entry) {
		pthread_mutex_unlock(&shared_rcio->mutex);
		return entry;
	}

	if (rcio_range_overlaps(filename, file_offset, region_size,
				num_regions)) {
		pthread_mutex_unlock(&shared_rcio->mutex);
		log_err("fio: rcio region range [%llu, %llu) for %s overlaps "
			"another RCIO tracker's range\n",
			(unsigned long long)file_offset,
			(unsigned long long)(file_offset +
					     region_size * num_regions),
			filename);
		return NULL;
	}

	entry = scalloc(1, sizeof(*entry));
	if (!entry)
		goto error;

	entry->filename = smalloc_strdup(filename);
	if (!entry->filename)
		goto error;

	entry->file_offset = file_offset;
	entry->region_size = region_size;
	entry->num_regions = num_regions;

	if (num_regions > UINT32_MAX) {
		log_err("fio: num_regions %" PRIu64
			" exceeds UINT32_MAX for %s\n", num_regions, filename);
		goto error;
	}

	if (num_regions > SIZE_MAX / sizeof(*entry->regions)) {
		log_err("fio: allocation overflow for %s\n",
			filename);
		goto error;
	}

	entry->regions = smalloc(num_regions * sizeof(*entry->regions));
	if (!entry->regions)
		goto error;
	entry->region_pos = smalloc(num_regions * sizeof(*entry->region_pos));
	if (!entry->region_pos)
		goto error;

	/*
	 * All regions start invalid (free).  The partitioned array has
	 * valid_count = 0, so regions[0..N-1] are all in the invalid list.
	 */
	for (i = 0; i < num_regions; i++) {
		entry->regions[i] = i;
		entry->region_pos[i] = i;
	}
	entry->valid_count = 0;

	if (mutex_init_pshared(&entry->mutex))
		goto error;

	flist_add(&entry->list, &shared_rcio->list);

	pthread_mutex_unlock(&shared_rcio->mutex);
	return entry;

error:
	if (entry) {
		sfree(entry->region_pos);
		sfree(entry->regions);
		sfree(entry->filename);
		sfree(entry);
	}
	pthread_mutex_unlock(&shared_rcio->mutex);
	log_err("fio: failed to allocate rcio tracker for %s\n",
		filename);
	return NULL;
}

/*
 * Release every shared tracker after all jobs have stopped using them.
 */
void free_all_shared_rcio(void)
{
	struct shared_rcio_entry *entry;
	struct flist_head *pos, *tmp;

	if (!shared_rcio)
		return;
	pthread_mutex_lock(&shared_rcio->mutex);

	flist_for_each_safe(pos, tmp, &shared_rcio->list) {
		entry = flist_entry(pos, struct shared_rcio_entry, list);
		flist_del(pos);
		pthread_mutex_destroy(&entry->mutex);
		sfree(entry->region_pos);
		sfree(entry->regions);
		sfree(entry->filename);
		sfree(entry);
	}

	pthread_mutex_unlock(&shared_rcio->mutex);
	pthread_mutex_destroy(&shared_rcio->mutex);
	sfree(shared_rcio);
	shared_rcio = NULL;
}

/*
 * Swap two array positions and update the reverse index for both regions.
 * Caller must hold entry->mutex.
 */
static inline void rcio_swap(struct shared_rcio_entry *entry,
			     uint64_t i, uint64_t j)
{
	uint32_t tmp = entry->regions[i];

	entry->regions[i] = entry->regions[j];
	entry->regions[j] = tmp;
	entry->region_pos[entry->regions[i]] = i;
	entry->region_pos[entry->regions[j]] = j;
}

/*
 * Move region at regions[idx] from invalid to valid partition.
 * Caller must hold entry->mutex.  Returns the region number.
 */
static inline uint64_t __mark_valid(struct shared_rcio_entry *entry, uint64_t idx)
{
	uint64_t region = entry->regions[idx];

	rcio_swap(entry, idx, entry->valid_count);
	entry->valid_count++;
	return region;
}

/*
 * Move region at regions[idx] from valid to invalid partition.
 * Caller must hold entry->mutex.  Returns the region number.
 */
static inline uint64_t __mark_invalid(struct shared_rcio_entry *entry, uint64_t idx)
{
	uint64_t region = entry->regions[idx];

	entry->valid_count--;
	rcio_swap(entry, idx, entry->valid_count);
	return region;
}

/*
 * Atomically pick a random region: writes move an invalid region to valid,
 * trims move a valid region to invalid, and reads leave a valid region intact.
 * Returns UINT64_MAX when no region is available for the requested direction.
 */
uint64_t rcio_pick_region(struct shared_rcio_entry *entry,
			  int ddir, struct frand_state *rs)
{
	uint64_t idx, region;

	pthread_mutex_lock(&entry->mutex);

	if (ddir == DDIR_WRITE) {
		/* pick from invalid list: [valid_count .. num_regions-1] */
		if (entry->valid_count >= entry->num_regions) {
			pthread_mutex_unlock(&entry->mutex);
			return UINT64_MAX;
		}
		idx = rand_between(rs, entry->valid_count,
				   entry->num_regions - 1);
		region = __mark_valid(entry, idx);
	} else if (ddir == DDIR_TRIM) {
		/* pick from valid list: [0 .. valid_count-1] */
		if (entry->valid_count == 0) {
			pthread_mutex_unlock(&entry->mutex);
			return UINT64_MAX;
		}
		idx = rand_between(rs, 0, entry->valid_count - 1);
		region = __mark_invalid(entry, idx);
	} else {
		/* DDIR_READ: pick from valid list, no state change */
		if (entry->valid_count == 0) {
			pthread_mutex_unlock(&entry->mutex);
			return UINT64_MAX;
		}
		idx = rand_between(rs, 0, entry->valid_count - 1);
		region = entry->regions[idx];
	}

	pthread_mutex_unlock(&entry->mutex);
	return region;
}

/*
 * Mark regions covered by a completed sequential I/O as valid for writes or
 * invalid for trims. Offsets are relative to the tracker's file_offset;
 * reads and zero-length completions do not change state.
 */
void rcio_mark_region(struct shared_rcio_entry *entry,
		      uint64_t offset, uint64_t buflen, int ddir)
{
	uint64_t rs = entry->region_size;
	uint64_t start, end;
	uint64_t r, i;

	if (ddir != DDIR_WRITE && ddir != DDIR_TRIM)
		return;

	/* Zero-byte completions touch no region; avoid end underflow. */
	if (!buflen)
		return;

	start = offset / rs;
	end = (offset + buflen - 1) / rs;

	pthread_mutex_lock(&entry->mutex);

	for (r = start; r <= end; r++) {
		if (r >= entry->num_regions)
			continue;
		i = entry->region_pos[r];
		if (ddir == DDIR_WRITE) {
			if (i >= entry->valid_count)
				__mark_valid(entry, i);
		} else {
			if (i < entry->valid_count)
				__mark_invalid(entry, i);
		}
	}

	pthread_mutex_unlock(&entry->mutex);
}
