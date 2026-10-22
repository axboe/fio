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
#include "fio.h"
#include "rcio.h"

#ifndef WIN32
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "flist.h"
#include "io_ddir.h"
#include "oslib/asprintf.h"
#include "log.h"
#include "lib/rand.h"
#include "minmax.h"

static FLIST_HEAD(shared_rcio_list);
static pthread_mutex_t shared_rcio_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rcio_save_state(struct shared_rcio_entry *entry, const char *path);

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
 * Atomically check that @path isn't already claimed by a different
 * tracker, and claim it for @self otherwise.  Doing the check and the
 * claim under a single shared_rcio_mutex critical section prevents two
 * trackers from both observing @path as unused and then each claiming
 * it.  Returns:
 *   0  - claimed for @self (or @self already held this same path)
 *  -EBUSY  - @path is already claimed by a different tracker
 *  -EINVAL - @self already holds a *different* path (conflicting
 *            rcio_state_file for the same file)
 *  -ENOMEM - allocation failure
 */
static int rcio_claim_state_file(struct shared_rcio_entry *self,
				 const char *path)
{
	struct flist_head *pos;
	struct shared_rcio_entry *entry;
	int ret = 0;

	pthread_mutex_lock(&shared_rcio_mutex);

	flist_for_each(pos, &shared_rcio_list) {
		entry = flist_entry(pos, struct shared_rcio_entry, list);
		if (entry != self && entry->state_file &&
		    !strcmp(entry->state_file, path)) {
			pthread_mutex_unlock(&shared_rcio_mutex);
			return -EBUSY;
		}
	}

	if (!self->state_file) {
		self->state_file = strdup(path);
		if (!self->state_file)
			ret = -ENOMEM;
	} else if (strcmp(self->state_file, path)) {
		ret = -EINVAL;
	}

	pthread_mutex_unlock(&shared_rcio_mutex);
	return ret;
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
 * Save eligible snapshots and release all trackers after jobs have stopped.
 * Withhold state after errors, interruption, or unfinished region I/O.
 * Returns nonzero if a snapshot was withheld or saving failed.
 */
int free_all_shared_rcio(bool save)
{
	struct shared_rcio_entry *entry;
	struct flist_head *pos, *tmp;
	int ret = 0;

	pthread_mutex_lock(&shared_rcio_mutex);

	flist_for_each_safe(pos, tmp, &shared_rcio_list) {
		entry = flist_entry(pos, struct shared_rcio_entry, list);
		flist_del(pos);
		if (entry->state_file) {
			if (entry->load_failed) {
				if (output_format & FIO_OUTPUT_NORMAL)
					log_info("rcio: not saving state to %s; "
						 "state initialization failed\n",
						 entry->state_file);
			} else if (!save || entry->save_failed ||
				 entry->pending_bytes) {
				log_err("rcio: not saving state to %s; "
					"run incomplete or device state uncertain\n",
					entry->state_file);
				ret = 1;
			} else if (rcio_save_state(entry, entry->state_file)) {
				log_err("rcio: failed to save state to %s\n",
					entry->state_file);
				ret = 1;
			} else if (output_format & FIO_OUTPUT_NORMAL)
				log_info("rcio: saved state to %s "
					 "(%llu/%llu valid)\n",
					 entry->state_file,
					 (unsigned long long)entry->valid_count,
					 (unsigned long long)entry->num_regions);
			free(entry->state_file);
		}
		pthread_mutex_destroy(&entry->mutex);
		free(entry->region_pos);
		free(entry->regions);
		free(entry->filename);
		free(entry);
	}

	pthread_mutex_unlock(&shared_rcio_mutex);
	return ret;
}

/*
 * Account for completed bytes from a randomly selected write/trim region.
 * An accounting mismatch makes the tracker unsafe to save.
 */
void rcio_complete_io(struct shared_rcio_entry *entry, uint64_t bytes)
{
	pthread_mutex_lock(&entry->mutex);
	if (bytes > entry->pending_bytes) {
		log_err("rcio: completed bytes exceed pending region bytes "
			"for %s\n", entry->filename);
		entry->save_failed = true;
	} else
		entry->pending_bytes -= bytes;
	pthread_mutex_unlock(&entry->mutex);
}

/*
 * Record each job's outcome before its files are freed. Errors, unlinks, or
 * incomplete work prevent saving shared state; skipped preconditioning after
 * a successful state load is not an incomplete run.
 */
void rcio_finish_job(struct thread_data *td, bool completed)
{
	struct fio_file *f;
	unsigned int i;

	for_each_file(td, f, i) {
		struct shared_rcio_entry *entry = f->rcio_shared;

		if (!entry)
			continue;
		pthread_mutex_lock(&entry->mutex);
		if (td->error || td->total_err_count ||
		    (td->o.unlink && f->filetype == FIO_TYPE_FILE) ||
		    (!completed && !(td->o.rcio_precondition &&
				      entry->load_succeeded && td->done)))
			entry->save_failed = true;
		pthread_mutex_unlock(&entry->mutex);
	}
}

/*
 * Report whether a write/trim job still has retries or unissued sequential
 * sub-blocks in its selected region, so it can finish the region before stopping.
 */
bool rcio_run_pending(struct thread_data *td)
{
	return td->o.rcio_bs && (td_write(td) || td_trim(td)) &&
	       (!io_u_rempty(&td->io_u_requeues) ||
		(td_random(td) && td->o.ddir_seq_nr > 1 &&
		 td->ddir_seq_nr > 1));
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
		/* Until completion, this whole region is unsafe to persist. */
		entry->pending_bytes += entry->region_size;
	} else if (ddir == DDIR_TRIM) {
		/* pick from valid list: [0 .. valid_count-1] */
		if (entry->valid_count == 0) {
			pthread_mutex_unlock(&entry->mutex);
			return (uint64_t)-1;
		}
		idx = rand_between(rs, 0, entry->valid_count - 1);
		region = __mark_invalid(entry, idx);
		entry->pending_bytes += entry->region_size;
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

#define RCIO_STATE_MAGIC	0x5243494f	/* "RCIO": Region-Constrained I/O State */
#define RCIO_STATE_VERSION	2

/*
 * On-disk header followed by num_regions uint32_t region indices.
 * The first valid_count indices identify written regions.
 */
struct rcio_state_header {
	uint32_t magic;		/* RCIO_STATE_MAGIC identifies an RCIO snapshot. */
	uint32_t version;	/* RCIO_STATE_VERSION defines the file format. */
	uint64_t file_offset;	/* Byte offset where the tracked range starts. */
	uint64_t region_size;	/* Bytes per region. */
	uint64_t num_regions;	/* Number of tracked regions and array entries. */
	uint64_t valid_count;	/* Length of the array's valid-region prefix. */
};

/*
 * Load region state from file.
 *
 * Returns:
 *   0        - state loaded successfully.
 *  -ENOENT   - file not found.
 *  -EBADMSG  - file present but incompatible/corrupt.
 *  Other negative errno values indicate an operational failure; the caller
 *  should fail initialization rather than silently precondition. Missing or
 *  incompatible/corrupt state permits an empty tracker and full preconditioning.
 */
static int rcio_load_state(struct shared_rcio_entry *entry, const char *path)
{
	struct rcio_state_header hdr;
	uint32_t *tmp = NULL;
	unsigned char *seen;
	uint64_t i;
	FILE *fp;
	size_t n;
	int ret;

	fp = fopen(path, "rb");
	if (!fp) {
		ret = -errno;
		if (ret != -ENOENT)
			log_err("rcio: cannot open %s: %m\n", path);
		return ret;
	}

	if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
		ret = ferror(fp) ? -EIO : -EBADMSG;
		if (ret == -EIO)
			log_err("rcio: %s: read error: %m\n", path);
		goto err;
	}

	if (hdr.magic != RCIO_STATE_MAGIC || hdr.version != RCIO_STATE_VERSION) {
		log_err("rcio: %s: bad magic or version\n", path);
		ret = -EBADMSG;
		goto err;
	}

	if (hdr.num_regions != entry->num_regions ||
	    hdr.region_size != entry->region_size ||
	    hdr.file_offset != entry->file_offset) {
		log_err("rcio: %s: incompatible geometry "
			"(file: %llu regions x %llu @ %llu, device: %llu x %llu @ %llu)\n",
			path,
			(unsigned long long)hdr.num_regions,
			(unsigned long long)hdr.region_size,
			(unsigned long long)hdr.file_offset,
			(unsigned long long)entry->num_regions,
			(unsigned long long)entry->region_size,
			(unsigned long long)entry->file_offset);
		ret = -EBADMSG;
		goto err;
	}

	if (hdr.valid_count > entry->num_regions) {
		log_err("rcio: %s: invalid valid_count %llu\n",
			path, (unsigned long long)hdr.valid_count);
		ret = -EBADMSG;
		goto err;
	}

	/*
	 * Read and validate into a temporary array so a short read or a
	 * corrupt permutation cannot leave the live tracker partially
	 * overwritten.
	 */
	tmp = malloc(entry->num_regions * sizeof(*tmp));
	if (!tmp) {
		log_err("rcio: %s: allocation failed\n", path);
		ret = -ENOMEM;
		goto err;
	}

	n = fread(tmp, sizeof(uint32_t), entry->num_regions, fp);
	if (n != entry->num_regions) {
		if (ferror(fp)) {
			log_err("rcio: %s: read error: %m\n", path);
			ret = -EIO;
		} else {
			log_err("rcio: %s: short read (%zu/%llu regions)\n",
				path, n, (unsigned long long)entry->num_regions);
			ret = -EBADMSG;
		}
		goto err;
	}

	/*
	 * The region array must be a permutation of [0, num_regions). Validate
	 * that every index is in range and appears exactly once so a corrupt
	 * state file cannot produce out-of-range offsets downstream.
	 */
	seen = calloc(entry->num_regions, 1);
	if (!seen) {
		log_err("rcio: %s: allocation failed\n", path);
		ret = -ENOMEM;
		goto err;
	}
	for (i = 0; i < entry->num_regions; i++) {
		uint64_t r = tmp[i];

		if (r >= entry->num_regions || seen[r]) {
			log_err("rcio: %s: corrupt region array\n", path);
			free(seen);
			ret = -EBADMSG;
			goto err;
		}
		seen[r] = 1;
	}
	free(seen);

	memcpy(entry->regions, tmp, entry->num_regions * sizeof(*tmp));
	entry->valid_count = hdr.valid_count;
	for (i = 0; i < entry->num_regions; i++)
		entry->region_pos[entry->regions[i]] = i;
	free(tmp);
	fclose(fp);
	return 0;

err:
	free(tmp);
	fclose(fp);
	return ret;
}

/*
 * fsync() the directory containing @path, so a preceding rename() into
 * @path is durable and not just visible.
 */
static int rcio_fsync_parent_dir(const char *path)
{
	char *dir_copy;
	int fd, ret;

	dir_copy = strdup(path);
	if (!dir_copy) {
		log_err("rcio: cannot allocate directory path for %s\n", path);
		return -1;
	}

	fd = open(dirname(dir_copy), O_RDONLY);
	if (fd < 0) {
		log_err("rcio: cannot open directory of %s for fsync: %m\n",
			path);
		free(dir_copy);
		return -1;
	}

	ret = fsync(fd);
	if (ret)
		log_err("rcio: fsync directory of %s failed: %m\n", path);

	close(fd);
	free(dir_copy);
	return ret;
}

/*
 * Write the header and region array to a temporary file, sync it, then rename
 * it over @path and sync the parent directory to publish a durable snapshot.
 * Caller must ensure the tracker is quiescent. Returns zero on success,
 * nonzero on failure.
 */
static int rcio_save_state(struct shared_rcio_entry *entry, const char *path)
{
	struct rcio_state_header hdr;
	char *tmp_path;
	FILE *fp;
	size_t n;
	int fd, ret;

	/*
	 * Write to a temporary file and rename it over the destination, so a
	 * crash, ENOSPC, or short write cannot publish partial state.
	 * Create the temporary file exclusively with restrictive permissions
	 * so a pre-created symlink cannot be followed.
	 */
	if (asprintf(&tmp_path, "%s.tmp.XXXXXX", path) < 0) {
		log_err("rcio: cannot allocate temporary path for %s\n", path);
		return -1;
	}

	fd = mkstemp(tmp_path);
	if (fd < 0) {
		log_err("rcio: cannot open %s for writing: %m\n", tmp_path);
		free(tmp_path);
		return -1;
	}
	fp = fdopen(fd, "wb");
	if (!fp) {
		log_err("rcio: cannot open stream for %s: %m\n", tmp_path);
		close(fd);
		unlink(tmp_path);
		free(tmp_path);
		return -1;
	}

	hdr.magic = RCIO_STATE_MAGIC;
	hdr.version = RCIO_STATE_VERSION;
	hdr.file_offset = entry->file_offset;
	hdr.region_size = entry->region_size;
	hdr.num_regions = entry->num_regions;
	hdr.valid_count = entry->valid_count;

	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		goto err;

	n = fwrite(entry->regions, sizeof(uint32_t), entry->num_regions, fp);
	if (n != entry->num_regions)
		goto err;

	/*
	 * Sync the temporary file's data before renaming it into place, so a
	 * crash right after the rename cannot leave the destination empty or
	 * truncated.
	 */
	if (fflush(fp) || fsync(fileno(fp))) {
		log_err("rcio: %s: fsync error: %m\n", tmp_path);
		fclose(fp);
		unlink(tmp_path);
		free(tmp_path);
		return -1;
	}

	if (fclose(fp)) {
		log_err("rcio: %s: close error: %m\n", tmp_path);
		unlink(tmp_path);
		free(tmp_path);
		return -1;
	}

	ret = rename(tmp_path, path);
	if (ret) {
		log_err("rcio: rename %s to %s failed: %m\n", tmp_path, path);
		unlink(tmp_path);
		free(tmp_path);
		return ret;
	}
	free(tmp_path);

	/*
	 * The rename itself is not durable until the directory entry that
	 * points at it is synced.
	 */
	return rcio_fsync_parent_dir(path);

err:
	log_err("rcio: %s: write error\n", tmp_path);
	fclose(fp);
	unlink(tmp_path);
	free(tmp_path);
	return -1;
}

/*
 * Validate the file's usable range, alignment, and I/O sizes for RCIO, then
 * attach its shared tracker. Claim and load persistent state once per tracker,
 * and invalidate the snapshot before device I/O can make it stale.
 * Returns false on invalid geometry or setup failure.
 */
static bool setup_rcio_file(struct thread_data *td, struct fio_file *f)
{
	uint64_t available = f->file_offset < f->real_file_size ?
			     f->real_file_size - f->file_offset : 0;
	uint64_t fsize = min(available, f->io_size);
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

	if (td->o.bs_is_seq_rand) {
		log_err("fio: bs_is_seq_rand is not supported with rcio_bs; "
			"block-size validation cannot account for the "
			"effective read and write sizes\n");
		return false;
	}

	if (td_random(td) && seq_nr > 1 &&
	    (td->o.nr_files > 1 || (td_read(td) && td_write(td)))) {
		log_err("fio: random RCIO runs longer than one I/O are not "
			"supported with mixed read/write directions or "
			"multiple files\n");
		return false;
	}

	if (!td_random(td) && td->o.ddir_seq_add &&
	    (td_write(td) || td_trim(td))) {
		uint64_t seq_add;

		if (td->o.ddir_seq_add < 0)
			seq_add = (uint64_t)(-(td->o.ddir_seq_add + 1)) + 1;
		else
			seq_add = td->o.ddir_seq_add;
		if (seq_add % rcio_bs) {
			log_err("fio: sequential write/trim skip must be a "
				"multiple of rcio_bs=%llu\n",
				(unsigned long long)rcio_bs);
			return false;
		}
		if (f->file_offset % rcio_bs) {
			log_err("fio: sequential RCIO skips require a "
				"region-aligned file offset\n");
			return false;
		}
		if (td->o.ddir_seq_add < 0 &&
		    min(f->real_file_size, f->io_size) % rcio_bs) {
			log_err("fio: reverse RCIO requires region-aligned "
				"wrap geometry (file offset and endpoint)\n");
			return false;
		}
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
	pthread_mutex_lock(&rcio->mutex);
	if (rcio->state_file && !td->o.use_thread) {
		log_err("fio: persistent RCIO tracker requires thread=1 "
			"for every sharing job (%s)\n", f->file_name);
		pthread_mutex_unlock(&rcio->mutex);
		return false;
	}
	f->rcio_shared = rcio;
	if (td->o.rcio_state_file) {
		int cret;

		if (rcio->in_use && !rcio->state_file) {
			log_err("fio: cannot attach rcio_state_file to an "
				"in-use tracker for %s\n", f->file_name);
			pthread_mutex_unlock(&rcio->mutex);
			return false;
		}
		cret = rcio_claim_state_file(rcio, td->o.rcio_state_file);

		if (cret == -EBUSY) {
			log_err("fio: rcio_state_file '%s' is already used "
				"by another RCIO tracker\n",
				td->o.rcio_state_file);
			pthread_mutex_unlock(&rcio->mutex);
			return false;
		} else if (cret == -EINVAL) {
			log_err("fio: conflicting rcio_state_file for %s: "
				"'%s' vs '%s'\n", f->file_name,
				rcio->state_file, td->o.rcio_state_file);
			pthread_mutex_unlock(&rcio->mutex);
			return false;
		} else if (cret == -ENOMEM) {
			log_err("fio: cannot allocate rcio_state_file path "
				"for %s\n", f->file_name);
			pthread_mutex_unlock(&rcio->mutex);
			return false;
		}
	}
	if (td->o.rcio_state_file && !rcio->load_attempted) {
		int lret;

		rcio->load_attempted = true;
		lret = rcio_load_state(rcio, td->o.rcio_state_file);
		if (lret == 0) {
			rcio->load_succeeded = true;
			if (output_format & FIO_OUTPUT_NORMAL)
				log_info("rcio: loaded state from %s "
					 "(%llu/%llu valid)\n",
					 td->o.rcio_state_file,
					 (unsigned long long)rcio->valid_count,
					 (unsigned long long)rcio->num_regions);
		} else if (lret == -ENOENT || lret == -EBADMSG) {
			if (output_format & FIO_OUTPUT_NORMAL)
				log_info("rcio: %s not found or incompatible, "
					 "preconditioning required\n",
					 td->o.rcio_state_file);
		} else {
			rcio->load_failed = true;
			log_err("fio: failed to load rcio_state_file %s\n",
				td->o.rcio_state_file);
			pthread_mutex_unlock(&rcio->mutex);
			return false;
		}
		/*
		 * Consume the snapshot before any job can change the device.
		 * A crash or failed save must not leave stale state reusable.
		 */
		if (unlink(rcio->state_file) && errno != ENOENT) {
			log_err("rcio: cannot invalidate %s: %m\n",
				rcio->state_file);
			rcio->load_failed = true;
		} else if (rcio_fsync_parent_dir(rcio->state_file)) {
			rcio->load_failed = true;
		}
	}
	if (rcio->load_failed) {
		/*
		 * load_attempted latches to true on the first attempt, so a
		 * job arriving after another job's load already failed would
		 * otherwise skip the block above and silently proceed with
		 * an empty tracker; check load_failed unconditionally so
		 * every sharer of this tracker observes the failure.
		 */
		log_err("fio: rcio_state_file %s initialization failed "
			"(see earlier error)\n", rcio->state_file);
		pthread_mutex_unlock(&rcio->mutex);
		return false;
	}
	rcio->in_use = true;
	pthread_mutex_unlock(&rcio->mutex);

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
	bool loaded = false, fresh = false;

	if (!td->o.rcio_bs)
		return true;

	if (td->o.read_iolog_file) {
		log_err("fio: read_iolog is not supported with rcio_bs; "
			"replayed extents bypass RCIO region validation\n");
		return false;
	}

	if (td_random(td) && td_write(td) &&
	    (td->o.experimental_verify || td->o.verify_only)) {
		log_err("fio: random RCIO writes do not support "
			"experimental_verify or verify_only\n");
		return false;
	}

	if (td_random(td) &&
	    ((td_read(td) && td->o.perc_rand[DDIR_READ] != 100) ||
	     (td_write(td) && td->o.perc_rand[DDIR_WRITE] != 100) ||
	     (td_trim(td) && td->o.perc_rand[DDIR_TRIM] != 100))) {
		log_err("fio: rcio_bs requires percentage_random=100 for "
			"every active direction of a random job\n");
		return false;
	}

	if (td->o.rcio_state_file && td->o.nr_files > 1) {
		log_err("fio: rcio_state_file is not supported with multiple "
			"files (nrfiles > 1)\n");
		return false;
	}

	if (td->o.rcio_state_file && !td->o.use_thread) {
		log_err("fio: rcio_state_file requires thread=1; region state "
			"is not saved in process mode\n");
		return false;
	}

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

	for_each_file(td, f, i) {
		if (td->o.unlink_each_loop && f->filetype == FIO_TYPE_FILE) {
			log_err("fio: unlink_each_loop is not supported with "
				"RCIO regular files (%s)\n", f->file_name);
			return false;
		}
		if (!setup_rcio_file(td, f))
			return false;
		pthread_mutex_lock(&f->rcio_shared->mutex);
		if (f->rcio_shared->load_succeeded)
			loaded = true;
		else
			fresh = true;
		pthread_mutex_unlock(&f->rcio_shared->mutex);
	}

	if (td->o.rcio_precondition && loaded) {
		if (fresh) {
			log_err("fio: precondition job mixes loaded and fresh "
				"RCIO trackers; use separate jobs\n");
			return false;
		}
		td->done = 1;
		td->o.pre_read = 0;
		if (output_format & FIO_OUTPUT_NORMAL)
			log_info("rcio: skipping precondition "
				 "(state loaded)\n");
	}

	return true;
}

bool rcio_check_jobs(void)
{
	struct fio_file *f, *other_f;
	unsigned int i, j;

	for_each_td(td) {
		if (!td->o.rcio_bs || !td->o.rcio_state_file)
			continue;

		for_each_td(other) {
			if (!other->o.rcio_bs || other->o.use_thread)
				continue;

			for_each_file(td, f, i) {
				for_each_file(other, other_f, j) {
					if (strcmp(f->file_name, other_f->file_name))
						continue;
					log_err("fio: persistent RCIO tracker "
						"requires thread=1 for every "
						"sharing job (%s)\n", f->file_name);
					return false;
				}
			}
		} end_for_each();
	} end_for_each();

	return true;
}

#else

bool rcio_check_jobs(void)
{
	return true;
}

bool init_rcio(struct thread_data *td)
{
	if (td->o.rcio_bs || td->o.rcio_state_file || td->o.rcio_precondition) {
		log_err("fio: RCIO is not supported on Windows\n");
		return false;
	}
	return true;
}

int free_all_shared_rcio(bool save)
{
	return 0;
}

void rcio_finish_job(struct thread_data *td, bool completed)
{
}

bool rcio_run_pending(struct thread_data *td)
{
	return false;
}

/* Initialization rejects RCIO, so no tracker can reach these I/O hooks. */
void rcio_complete_io(struct shared_rcio_entry *entry, uint64_t bytes)
{
	assert(!entry);
}

void rcio_mark_region(struct shared_rcio_entry *entry,
		      uint64_t offset, uint64_t buflen, int ddir)
{
	assert(!entry);
}

uint64_t rcio_pick_region(struct shared_rcio_entry *entry,
			  int ddir, struct frand_state *rs)
{
	assert(!entry);
	return (uint64_t)-1;
}

#endif
