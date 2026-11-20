/**
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2026 Sandisk Corporation or its affiliates.
 */

#include "fio.h"
#include "rcio.h"

#ifndef WIN32
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "io_ddir.h"
#include "lib/rand.h"
#include "log.h"
#include "pshared.h"
#include "smalloc.h"

static struct {
	struct flist_head list;
	pthread_mutex_t mutex;
} *shared_rcio;

int init_shared_rcio(void)
{
	bool needed = false;

	for_each_td(td) {
		if (td->o.rcio_size) {
			needed = true;
			break;
		}
	} end_for_each();
	if (!needed)
		return 0;

	for_each_td(td) {
		if (!td->o.rcio_size && td->o.read_iolog_file) {
			log_err("fio: non-RCIO read_iolog jobs may access the "
				"RCIO target outside the tracker\n");
			return 1;
		}
	} end_for_each();

	if (shared_rcio)
		return 0;

	shared_rcio = scalloc(1, sizeof(*shared_rcio));
	if (!shared_rcio) {
		log_err("fio: failed to allocate shared RCIO registry\n");
		return 1;
	}

	INIT_FLIST_HEAD(&shared_rcio->list);
	if (mutex_init_pshared(&shared_rcio->mutex)) {
		sfree(shared_rcio);
		shared_rcio = NULL;
		log_err("fio: failed to initialize shared RCIO registry lock\n");
		return 1;
	}

	return 0;
}

static struct shared_rcio_entry *
find_shared_rcio(const char *filename, uint64_t file_offset,
		 uint64_t region_size, uint64_t num_regions)
{
	struct flist_head *pos;

	flist_for_each(pos, &shared_rcio->list) {
		struct shared_rcio_entry *entry;

		entry = flist_entry(pos, struct shared_rcio_entry, list);
		if (!strcmp(entry->filename, filename) &&
		    entry->file_offset == file_offset &&
		    entry->region_size == region_size &&
		    entry->num_regions == num_regions)
			return entry;
	}

	return NULL;
}

static void rcio_swap(struct shared_rcio_entry *entry, uint64_t i, uint64_t j)
{
	uint32_t tmp = entry->regions[i];

	entry->regions[i] = entry->regions[j];
	entry->regions[j] = tmp;
	entry->region_pos[entry->regions[i]] = i;
	entry->region_pos[entry->regions[j]] = j;
}

static void rcio_mark_valid(struct shared_rcio_entry *entry, uint64_t idx)
{
	rcio_swap(entry, idx, entry->valid_count);
	entry->valid_count++;
}

static void rcio_mark_free(struct shared_rcio_entry *entry, uint64_t idx)
{
	entry->valid_count--;
	rcio_swap(entry, idx, entry->valid_count);
}

static uint64_t rcio_reserve_region(struct shared_rcio_entry *entry,
				    uint64_t idx, uint64_t reserved_start,
				    int ddir)
{
	uint64_t region;

	if (ddir != DDIR_WRITE) {
		rcio_mark_free(entry, idx);
		idx = entry->valid_count;
	}

	region = entry->regions[idx];
	rcio_swap(entry, idx, reserved_start - 1);
	entry->region_ddir[region] = ddir;
	entry->reserved_count++;
	return region;
}

static void free_rcio_entry(struct shared_rcio_entry *entry)
{
	pthread_mutex_destroy(&entry->mutex);
	sfree(entry->region_ddir);
	sfree(entry->region_pos);
	sfree(entry->regions);
	sfree(entry->filename);
	sfree(entry);
}

int free_all_shared_rcio(void)
{
	struct flist_head *pos, *tmp;
	int ret = 0;

	if (!shared_rcio)
		return 0;

	pthread_mutex_lock(&shared_rcio->mutex);
	flist_for_each_safe(pos, tmp, &shared_rcio->list) {
		struct shared_rcio_entry *entry;

		entry = flist_entry(pos, struct shared_rcio_entry, list);
		flist_del(pos);
		if (entry->failed || entry->reserved_count) {
			log_err("rcio: tracker for %s stopped with uncertain "
				"or in-flight region state\n", entry->filename);
			ret = 1;
		}
		free_rcio_entry(entry);
	}
	pthread_mutex_unlock(&shared_rcio->mutex);
	pthread_mutex_destroy(&shared_rcio->mutex);
	sfree(shared_rcio);
	shared_rcio = NULL;

	return ret;
}

struct shared_rcio_entry *
get_shared_rcio(const char *filename, uint64_t file_offset,
		uint64_t region_size, uint64_t num_regions)
{
	struct shared_rcio_entry *entry;
	uint64_t i;

	if (!shared_rcio || !filename || !region_size || !num_regions ||
	    num_regions > UINT32_MAX ||
	    num_regions > (UINT64_MAX - file_offset) / region_size ||
	    num_regions > SIZE_MAX / sizeof(*entry->regions) ||
	    num_regions > SIZE_MAX / sizeof(*entry->region_ddir)) {
		log_err("fio: invalid RCIO tracker geometry for %s\n",
			filename ? filename : "(unknown)");
		return NULL;
	}

	pthread_mutex_lock(&shared_rcio->mutex);
	entry = find_shared_rcio(filename, file_offset, region_size, num_regions);
	if (entry)
		goto done;

	if (!flist_empty(&shared_rcio->list)) {
		log_err("fio: RCIO jobs must use one target and range\n");
		entry = NULL;
		goto done;
	}

	entry = scalloc(1, sizeof(*entry));
	if (!entry)
		goto error;

	entry->filename = smalloc_strdup(filename);
	entry->regions = smalloc(num_regions * sizeof(*entry->regions));
	entry->region_pos = smalloc(num_regions * sizeof(*entry->region_pos));
	entry->region_ddir = smalloc(num_regions * sizeof(*entry->region_ddir));
	if (!entry->filename || !entry->regions || !entry->region_pos ||
	    !entry->region_ddir)
		goto error;

	entry->file_offset = file_offset;
	entry->region_size = region_size;
	entry->num_regions = num_regions;
	for (i = 0; i < num_regions; i++) {
		entry->regions[i] = i;
		entry->region_pos[i] = i;
		entry->region_ddir[i] = -1;
	}

	if (mutex_init_pshared(&entry->mutex))
		goto error;

	flist_add(&entry->list, &shared_rcio->list);
	goto done;

error:
	if (entry) {
		sfree(entry->region_ddir);
		sfree(entry->region_pos);
		sfree(entry->regions);
		sfree(entry->filename);
		sfree(entry);
	}
	entry = NULL;
	log_err("fio: failed to allocate RCIO tracker for %s\n", filename);
done:
	pthread_mutex_unlock(&shared_rcio->mutex);
	return entry;
}

uint64_t rcio_pick_region(struct shared_rcio_entry *entry, int ddir,
			  struct frand_state *rs)
{
	uint64_t reserved_start, idx, region;

	pthread_mutex_lock(&entry->mutex);
	if (entry->failed) {
		pthread_mutex_unlock(&entry->mutex);
		return RCIO_REGION_FAILED;
	}

	reserved_start = entry->num_regions - entry->reserved_count;
	if (ddir == DDIR_WRITE) {
		if (entry->valid_count == reserved_start)
			goto unavailable;
		idx = rand_between(rs, entry->valid_count, reserved_start - 1);
	} else if (ddir == DDIR_READ || ddir == DDIR_TRIM) {
		if (!entry->valid_count)
			goto unavailable;
		idx = rand_between(rs, 0, entry->valid_count - 1);
	} else {
		log_err("rcio: invalid I/O direction %d for %s\n", ddir,
			entry->filename);
		pthread_mutex_unlock(&entry->mutex);
		return RCIO_REGION_FAILED;
	}

	region = rcio_reserve_region(entry, idx, reserved_start, ddir);
	pthread_mutex_unlock(&entry->mutex);
	return region;

unavailable:
	region = entry->reserved_count ? RCIO_REGION_RESERVED : UINT64_MAX;
	pthread_mutex_unlock(&entry->mutex);
	return region;
}

int rcio_complete_region(struct shared_rcio_entry *entry, uint64_t region,
			 int ddir)
{
	uint64_t reserved_start, idx;

	pthread_mutex_lock(&entry->mutex);
	reserved_start = entry->num_regions - entry->reserved_count;
	if (region >= entry->num_regions ||
	    (ddir != DDIR_READ && ddir != DDIR_WRITE && ddir != DDIR_TRIM)) {
		log_err("rcio: invalid region completion for %s\n",
			entry->filename);
		pthread_mutex_unlock(&entry->mutex);
		return -EINVAL;
	}

	idx = entry->region_pos[region];
	if (idx < reserved_start || entry->region_ddir[region] != ddir) {
		log_err("rcio: invalid completion for reserved region %" PRIu64
			" in %s\n", region, entry->filename);
		pthread_mutex_unlock(&entry->mutex);
		return -EINVAL;
	}

	/* Release it to free, then make reads and writes valid. */
	rcio_swap(entry, idx, reserved_start);
	entry->reserved_count--;
	entry->region_ddir[region] = -1;
	if (ddir != DDIR_TRIM)
		rcio_mark_valid(entry, reserved_start);

	pthread_mutex_unlock(&entry->mutex);
	return 0;
}

void rcio_fail(struct shared_rcio_entry *entry)
{
	pthread_mutex_lock(&entry->mutex);
	if (!entry->failed)
		log_err("rcio: I/O failure leaves region state uncertain for %s\n",
			entry->filename);
	entry->failed = true;
	pthread_mutex_unlock(&entry->mutex);
}

static int same_rcio_target(const char *first, const char *second)
{
	struct stat a, b;

	if (!strcmp(first, second))
		return 1;
	if (stat(first, &a)) {
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		log_err("fio: cannot stat RCIO target %s: %s\n", first,
			strerror(errno));
		return -1;
	}
	if (stat(second, &b)) {
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		log_err("fio: cannot stat target %s: %s\n", second,
			strerror(errno));
		return -1;
	}
	if ((S_ISBLK(a.st_mode) && S_ISBLK(b.st_mode)) ||
	    (S_ISCHR(a.st_mode) && S_ISCHR(b.st_mode)))
		return a.st_rdev == b.st_rdev;
	return a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}

int init_rcio_jobs(void)
{
	struct shared_rcio_entry *entry = NULL;

	if (!shared_rcio)
		return 0;

	for_each_td(td) {
		struct fio_file *f;
		uint64_t available, size;

		if (!td->o.rcio_size)
			continue;
		if (td->runstate == TD_REAPED) {
			log_err("fio: RCIO job file setup failed\n");
			return 1;
		}
		f = td->files[0];
		if (f->file_offset >= f->real_file_size) {
			log_err("fio: invalid RCIO offset for %s\n", f->file_name);
			return 1;
		}
		available = f->real_file_size - f->file_offset;
		size = f->io_size < available ? f->io_size : available;
		if (!size || size % td->o.rcio_size ||
		    f->file_offset % td->o.rcio_size) {
			log_err("fio: RCIO range for %s must contain whole, "
				"aligned regions\n", f->file_name);
			return 1;
		}
		if (td->o.random_generator == FIO_RAND_GEN_TAUSWORTHE &&
		    size / td->o.rcio_size > INT_MAX) {
			log_err("fio: RCIO region count requires "
				"random_generator=tausworthe64\n");
			return 1;
		}
		entry = get_shared_rcio(f->file_name, f->file_offset,
					td->o.rcio_size, size / td->o.rcio_size);
		if (!entry)
			return 1;
		f->rcio_shared = entry;
	} end_for_each();

	if (!entry)
		return 0;
	for_each_td(td) {
		struct fio_file *f;
		unsigned int i;

		if (td->o.rcio_size)
			continue;
		for_each_file(td, f, i) {
			int same = same_rcio_target(entry->filename, f->file_name);

			if (same < 0)
				return 1;
			if (same) {
				log_err("fio: non-RCIO job shares the RCIO "
					"target %s\n", f->file_name);
				return 1;
			}
		}
	} end_for_each();
	return 0;
}

#else

int init_shared_rcio(void)
{
	return 0;
}

int init_rcio_jobs(void)
{
	return 0;
}

int free_all_shared_rcio(void)
{
	return 0;
}

uint64_t rcio_pick_region(struct shared_rcio_entry *entry, int ddir,
			  struct frand_state *rs)
{
	log_err("fio: RCIO is not supported on Windows\n");
	return RCIO_REGION_FAILED;
}

int rcio_complete_region(struct shared_rcio_entry *entry, uint64_t region,
			 int ddir)
{
	log_err("fio: RCIO is not supported on Windows\n");
	return -1;
}

void rcio_fail(struct shared_rcio_entry *entry)
{
	log_err("fio: RCIO is not supported on Windows\n");
}
#endif
