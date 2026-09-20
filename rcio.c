/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2026 Sandisk Corporation or its affiliates.
 */

/*
 * Region-constrained I/O (RCIO) region tracker.
 *
 * Maintains a partitioned array of region indices shared across threads.
 * See rcio.h for the data-structure description.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "rcio.h"
#include "flist.h"
#include "io_ddir.h"
#include "log.h"
#include "lib/rand.h"
#include "fio.h"
#include "minmax.h"

static FLIST_HEAD(shared_rcio_list);
static pthread_mutex_t shared_rcio_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Find a tracker matching the file and region geometry, or return NULL.
 * Caller must hold shared_rcio_mutex.
 */
static struct shared_rcio_entry *
find_shared_rcio(const char *filename, uint64_t file_offset,
		 uint64_t region_size, uint64_t num_regions)
{
	struct flist_head *pos;
	struct shared_rcio_entry *entry;

	flist_for_each(pos, &shared_rcio_list) {
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
 * what is actually valid on device.  Caller must hold shared_rcio_mutex.
 */
static bool rcio_range_overlaps(const char *filename, uint64_t file_offset,
				uint64_t region_size, uint64_t num_regions)
{
	struct flist_head *pos;
	struct shared_rcio_entry *entry;
	uint64_t start = file_offset;
	uint64_t end = file_offset + region_size * num_regions;

	flist_for_each(pos, &shared_rcio_list) {
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

	pthread_mutex_lock(&shared_rcio_mutex);

	entry = find_shared_rcio(filename, file_offset, region_size,
				 num_regions);
	if (entry) {
		pthread_mutex_unlock(&shared_rcio_mutex);
		return entry;
	}

	if (rcio_range_overlaps(filename, file_offset, region_size,
				num_regions)) {
		pthread_mutex_unlock(&shared_rcio_mutex);
		log_err("fio: rcio region range [%llu, %llu) for %s overlaps "
			"another RCIO tracker's range\n",
			(unsigned long long)file_offset,
			(unsigned long long)(file_offset +
					     region_size * num_regions),
			filename);
		return NULL;
	}

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		goto error;

	entry->filename = strdup(filename);
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

	entry->regions = malloc(num_regions * sizeof(*entry->regions));
	if (!entry->regions)
		goto error;
	entry->region_pos = malloc(num_regions * sizeof(*entry->region_pos));
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

	if (pthread_mutex_init(&entry->mutex, NULL))
		goto error;

	flist_add(&entry->list, &shared_rcio_list);

	pthread_mutex_unlock(&shared_rcio_mutex);
	return entry;

error:
	if (entry) {
		free(entry->region_pos);
		free(entry->regions);
		free(entry->filename);
		free(entry);
	}
	pthread_mutex_unlock(&shared_rcio_mutex);
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

	pthread_mutex_lock(&shared_rcio_mutex);

	flist_for_each_safe(pos, tmp, &shared_rcio_list) {
		entry = flist_entry(pos, struct shared_rcio_entry, list);
		flist_del(pos);
		pthread_mutex_destroy(&entry->mutex);
		free(entry->region_pos);
		free(entry->regions);
		free(entry->filename);
		free(entry);
	}

	pthread_mutex_unlock(&shared_rcio_mutex);
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
 * Returns (uint64_t)-1 when no region is available for the requested direction.
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
			return (uint64_t)-1;
		}
		idx = rand_between(rs, entry->valid_count,
				   entry->num_regions - 1);
		region = __mark_valid(entry, idx);
	} else if (ddir == DDIR_TRIM) {
		/* pick from valid list: [0 .. valid_count-1] */
		if (entry->valid_count == 0) {
			pthread_mutex_unlock(&entry->mutex);
			return (uint64_t)-1;
		}
		idx = rand_between(rs, 0, entry->valid_count - 1);
		region = __mark_invalid(entry, idx);
	} else {
		/* DDIR_READ: pick from valid list, no state change */
		if (entry->valid_count == 0) {
			pthread_mutex_unlock(&entry->mutex);
			return (uint64_t)-1;
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

/*
 * Validate the file's usable range, alignment, and I/O sizes for RCIO, then
 * attach its shared tracker. Returns false on invalid geometry or setup failure.
 */
static bool setup_rcio_file(struct thread_data *td, struct fio_file *f)
{
	uint64_t fsize = min(f->real_file_size, f->io_size);
	struct shared_rcio_entry *rcio;
	uint64_t rcio_bs = td->o.rcio_bs;
	uint64_t rcio_blocks = fsize / rcio_bs;
	unsigned int seq_nr = td->o.ddir_seq_nr ? td->o.ddir_seq_nr : 1;

	if (!rcio_blocks) {
		log_err("fio: rcio_bs=%llu is "
			"larger than the usable file size %llu\n",
			(unsigned long long)rcio_bs,
			(unsigned long long)fsize);
		return false;
	}

	if (rcio_bs % td->o.ba[DDIR_WRITE] ||
	    rcio_bs % td->o.ba[DDIR_READ] ||
	    rcio_bs % td->o.ba[DDIR_TRIM]) {
		log_err("fio: rcio_bs=%llu must "
			"be a multiple of block alignment\n",
			(unsigned long long)rcio_bs);
		return false;
	}

	/*
	 * Reads only need to stay within one region; they don't
	 * transition tracker state.
	 */
	if (td_read(td) && td->o.max_bs[DDIR_READ] > rcio_bs / seq_nr) {
		log_err("fio: rcio_bs=%llu must be at least the "
			"maximum read block size times the "
			"sequential run length (%u), so a run "
			"started by one RCIO pick cannot cross into "
			"another region\n",
			(unsigned long long)rcio_bs, seq_nr);
		return false;
	}

	/*
	 * rcio_pick_region() transitions an entire region at once for
	 * writes and trims, so a write/trim (and its full sequential
	 * run) must exactly cover the region: a fixed block size that
	 * fully tiles rcio_bs.  Otherwise a region marked valid by a
	 * partial write can expose uninitialized data, and a region
	 * marked invalid by a partial trim can leave stale data
	 * behind.
	 */
	if (td_write(td) &&
	    (td->o.min_bs[DDIR_WRITE] != td->o.max_bs[DDIR_WRITE] ||
	     (uint64_t)td->o.max_bs[DDIR_WRITE] * seq_nr != rcio_bs)) {
		log_err("fio: rcio_bs=%llu requires a fixed write "
			"block size whose size times the sequential "
			"run length (%u) exactly equals rcio_bs, so "
			"each write fully covers the region it marks "
			"valid\n",
			(unsigned long long)rcio_bs, seq_nr);
		return false;
	}

	if (td_trim(td) &&
	    (td->o.min_bs[DDIR_TRIM] != td->o.max_bs[DDIR_TRIM] ||
	     (uint64_t)td->o.max_bs[DDIR_TRIM] * seq_nr != rcio_bs)) {
		log_err("fio: rcio_bs=%llu requires a fixed trim "
			"block size whose size times the sequential "
			"run length (%u) exactly equals rcio_bs, so "
			"each trim fully covers the region it marks "
			"invalid\n",
			(unsigned long long)rcio_bs, seq_nr);
		return false;
	}

	rcio = get_shared_rcio(f->file_name, f->file_offset, rcio_bs,
			       rcio_blocks);
	if (!rcio) {
		log_err("fio: failed to allocate RCIO region tracker "
			"for %s\n", f->file_name);
		return false;
	}
	f->rcio_shared = rcio;

	return true;
}

/*
 * Set up RCIO region tracking for all files.  RCIO applies
 * to both random and sequential jobs (sequential preconditioning marks
 * regions valid at completion), so this is independent of the random map.
 */
bool init_rcio(struct thread_data *td)
{
	struct fio_file *f;
	unsigned int i;

	if (!td->o.rcio_bs)
		return true;

	if (td->o.zone_mode == ZONE_MODE_ZBD ||
	    td->o.zone_mode == ZONE_MODE_STRIDED) {
		log_err("fio: rcio_bs is not supported with zonemode=zbd or "
			"zonemode=strided\n");
		return false;
	}

	if (td_trimwrite(td)) {
		log_err("fio: rcio_bs is not supported with "
			"trimwrite/randtrimwrite: its paired write reuses "
			"the trim's region directly rather than picking from "
			"the (disjoint) invalid partition\n");
		return false;
	}

	if (td->o.rw_seq == RW_SEQ_IDENT &&
	    (td_write(td) || td_trim(td)) && td->o.ddir_seq_nr > 1) {
		log_err("fio: rcio_bs is not supported with "
			"rw_sequencer=identical and a sequential run length "
			"greater than 1 for writes/trims: the region is "
			"picked once per run but only its first sub-block "
			"would actually be covered\n");
		return false;
	}

	if (td->o.trim_backlog) {
		log_err("fio: rcio_bs is not supported with trim_backlog: "
			"backlog trims bypass region selection, so a trimmed "
			"region would stay marked valid and later reads could "
			"target discarded data\n");
		return false;
	}

	for_each_file(td, f, i)
		if (!setup_rcio_file(td, f))
			return false;

	return true;
}
