/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "compiler/compiler.h"
#include "os/os.h"
#include "file.h"
#include "fio.h"
#include "lib/pow2.h"
#include "log.h"
#include "oslib/asprintf.h"
#include "smalloc.h"
#include "verify.h"
#include "pshared.h"
#include "zbd.h"

static bool is_valid_offset(const struct fio_file *f, uint64_t offset)
{
	return (uint64_t)(offset - f->file_offset) < f->io_size;
}

static inline unsigned int zbd_zone_idx(const struct fio_file *f,
					struct fio_zone_info *zone)
{
	return zone - f->zbd_info->zone_info;
}

/**
 * zbd_offset_to_zone_idx - convert an offset into a zone number
 * @f: file pointer.
 * @offset: offset in bytes. If this offset is in the first zone_size bytes
 *	    past the disk size then the index of the sentinel is returned.
 */
static unsigned int zbd_offset_to_zone_idx(const struct fio_file *f,
					   uint64_t offset)
{
	uint32_t zone_idx;

	if (f->zbd_info->zone_size_log2 > 0)
		zone_idx = offset >> f->zbd_info->zone_size_log2;
	else
		zone_idx = offset / f->zbd_info->zone_size;

	return min(zone_idx, f->zbd_info->nr_zones);
}

/**
 * zbd_zone_end - Return zone end location
 * @z: zone info pointer.
 */
static inline uint64_t zbd_zone_end(const struct fio_zone_info *z)
{
	return (z+1)->start;
}

/**
 * zbd_zone_capacity_end - Return zone capacity limit end location
 * @z: zone info pointer.
 */
static inline uint64_t zbd_zone_capacity_end(const struct fio_zone_info *z)
{
	return z->start + z->capacity;
}

/**
 * zbd_zone_remainder - Return the number of bytes that are still available for
 *                      writing before the zone gets full
 * @z: zone info pointer.
 */
static inline uint64_t zbd_zone_remainder(struct fio_zone_info *z)
{
	if (z->wp >= zbd_zone_capacity_end(z))
		return 0;

	return zbd_zone_capacity_end(z) - z->wp;
}

/**
 * zbd_zone_full - verify whether a minimum number of bytes remain in a zone
 * @f: file pointer.
 * @z: zone info pointer.
 * @required: minimum number of bytes that must remain in a zone.
 *
 * The caller must hold z->mutex.
 */
static bool zbd_zone_full(const struct fio_file *f, struct fio_zone_info *z,
			  uint64_t required)
{
	assert((required & 511) == 0);

	return z->has_wp && required > zbd_zone_remainder(z);
}

static void zone_lock(struct thread_data *td, const struct fio_file *f,
		      struct fio_zone_info *z)
{
#ifndef NDEBUG
	unsigned int const nz = zbd_zone_idx(f, z);
	/* A thread should never lock zones outside its working area. */
	assert(f->min_zone <= nz && nz < f->max_zone);
	assert(z->has_wp);
#endif

	/*
	 * Lock the io_u target zone. The zone will be unlocked if io_u offset
	 * is changed or when io_u completes and zbd_put_io() executed.
	 * To avoid multiple jobs doing asynchronous I/Os from deadlocking each
	 * other waiting for zone locks when building an io_u batch, first
	 * only trylock the zone. If the zone is already locked by another job,
	 * process the currently queued I/Os so that I/O progress is made and
	 * zones unlocked.
	 */
	if (pthread_mutex_trylock(&z->mutex) != 0) {
		if (!td_ioengine_flagged(td, FIO_SYNCIO))
			io_u_quiesce(td);
		pthread_mutex_lock(&z->mutex);
	}
}

static inline void zone_unlock(struct fio_zone_info *z)
{
	assert(z->has_wp);
	pthread_mutex_unlock(&z->mutex);
}

static inline struct fio_zone_info *zbd_get_zone(const struct fio_file *f,
						 unsigned int zone_idx)
{
	return &f->zbd_info->zone_info[zone_idx];
}

static inline struct fio_zone_info *
zbd_offset_to_zone(const struct fio_file *f,  uint64_t offset)
{
	return zbd_get_zone(f, zbd_offset_to_zone_idx(f, offset));
}

static bool accounting_vdb(struct thread_data *td, const struct fio_file *f)
{
	return td->o.zrt.u.f && td_write(td);
}

/**
 * zbd_get_zoned_model - Get a device zoned model
 * @td: FIO thread data
 * @f: FIO file for which to get model information
 */
static int zbd_get_zoned_model(struct thread_data *td, struct fio_file *f,
			       enum zbd_zoned_model *model)
{
	int ret;

	if (f->filetype == FIO_TYPE_PIPE) {
		log_err("zonemode=zbd does not support pipes\n");
		return -EINVAL;
	}

	/* If regular file, always emulate zones inside the file. */
	if (f->filetype == FIO_TYPE_FILE) {
		*model = ZBD_NONE;
		return 0;
	}

	if (td->io_ops && td->io_ops->get_zoned_model)
		ret = td->io_ops->get_zoned_model(td, f, model);
	else
		ret = blkzoned_get_zoned_model(td, f, model);
	if (ret < 0) {
		td_verror(td, errno, "get zoned model failed");
		log_err("%s: get zoned model failed (%d).\n",
			f->file_name, errno);
	}

	return ret;
}

/**
 * zbd_report_zones - Get zone information
 * @td: FIO thread data.
 * @f: FIO file for which to get zone information
 * @offset: offset from which to report zones
 * @zones: Array of struct zbd_zone
 * @nr_zones: Size of @zones array
 *
 * Get zone information into @zones starting from the zone at offset @offset
 * for the device specified by @f.
 *
 * Returns the number of zones reported upon success and a negative error code
 * upon failure. If the zone report is empty, always assume an error (device
 * problem) and return -EIO.
 */
static int zbd_report_zones(struct thread_data *td, struct fio_file *f,
			    uint64_t offset, struct zbd_zone *zones,
			    unsigned int nr_zones)
{
	int ret;

	if (td->io_ops && td->io_ops->report_zones)
		ret = td->io_ops->report_zones(td, f, offset, zones, nr_zones);
	else
		ret = blkzoned_report_zones(td, f, offset, zones, nr_zones);
	if (ret < 0) {
		td_verror(td, errno, "report zones failed");
		log_err("%s: report zones from sector %"PRIu64" failed (nr_zones=%d; errno=%d).\n",
			f->file_name, offset >> 9, nr_zones, errno);
	} else if (ret == 0) {
		td_verror(td, errno, "Empty zone report");
		log_err("%s: report zones from sector %"PRIu64" is empty.\n",
			f->file_name, offset >> 9);
		ret = -EIO;
	}

	return ret;
}

/**
 * zbd_reset_wp - reset the write pointer of a range of zones
 * @td: FIO thread data.
 * @f: FIO file for which to reset zones
 * @offset: Starting offset of the first zone to reset
 * @length: Length of the range of zones to reset
 *
 * Reset the write pointer of all zones in the range @offset...@offset+@length.
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_reset_wp(struct thread_data *td, struct fio_file *f,
			uint64_t offset, uint64_t length)
{
	int ret;

	if (td->io_ops && td->io_ops->reset_wp)
		ret = td->io_ops->reset_wp(td, f, offset, length);
	else
		ret = blkzoned_reset_wp(td, f, offset, length);
	if (ret < 0) {
		td_verror(td, errno, "resetting wp failed");
		log_err("%s: resetting wp for %"PRIu64" sectors at sector %"PRIu64" failed (%d).\n",
			f->file_name, length >> 9, offset >> 9, errno);
	}

	return ret;
}

/**
 * __zbd_reset_zone - reset the write pointer of a single zone
 * @td: FIO thread data.
 * @f: FIO file associated with the disk for which to reset a write pointer.
 * @z: Zone to reset.
 *
 * Returns 0 upon success and a negative error code upon failure.
 *
 * The caller must hold z->mutex.
 */
static int __zbd_reset_zone(struct thread_data *td, struct fio_file *f,
			    struct fio_zone_info *z)
{
	uint64_t offset = z->start;
	uint64_t length = (z+1)->start - offset;
	uint64_t data_in_zone = z->wp - z->start;
	int ret = 0;

	if (!data_in_zone)
		return 0;

	assert(is_valid_offset(f, offset + length - 1));

	dprint(FD_ZBD, "%s: resetting wp of zone %u.\n",
	       f->file_name, zbd_zone_idx(f, z));

	switch (f->zbd_info->model) {
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		ret = zbd_reset_wp(td, f, offset, length);
		if (ret < 0)
			return ret;
		break;
	default:
		break;
	}

	if (accounting_vdb(td, f)) {
		pthread_mutex_lock(&f->zbd_info->mutex);
		f->zbd_info->wp_valid_data_bytes -= data_in_zone;
		pthread_mutex_unlock(&f->zbd_info->mutex);
	}

	z->wp = z->start;

	td->ts.nr_zone_resets++;

	return ret;
}

/**
 * zbd_write_zone_put - Remove a zone from the write target zones array.
 * @td: FIO thread data.
 * @f: FIO file that has the write zones array to remove.
 * @zone_idx: Index of the zone to remove.
 *
 * The caller must hold f->zbd_info->mutex.
 */
static void zbd_write_zone_put(struct thread_data *td, const struct fio_file *f,
			       struct fio_zone_info *z)
{
	uint32_t zi;

	if (!z->write)
		return;

	for (zi = 0; zi < f->zbd_info->num_write_zones; zi++) {
		if (zbd_get_zone(f, f->zbd_info->write_zones[zi]) == z)
			break;
	}
	if (zi == f->zbd_info->num_write_zones)
		return;

	dprint(FD_ZBD, "%s: removing zone %u from write zone array\n",
	       f->file_name, zbd_zone_idx(f, z));

	memmove(f->zbd_info->write_zones + zi,
		f->zbd_info->write_zones + zi + 1,
		(ZBD_MAX_WRITE_ZONES - (zi + 1)) *
		sizeof(f->zbd_info->write_zones[0]));

	f->zbd_info->num_write_zones--;
	td->num_write_zones--;
	z->write = 0;
}

/**
 * zbd_reset_zone - reset the write pointer of a single zone and remove the zone
 *                  from the array of write zones.
 * @td: FIO thread data.
 * @f: FIO file associated with the disk for which to reset a write pointer.
 * @z: Zone to reset.
 *
 * Returns 0 upon success and a negative error code upon failure.
 *
 * The caller must hold z->mutex.
 */
static int zbd_reset_zone(struct thread_data *td, struct fio_file *f,
			  struct fio_zone_info *z)
{
	int ret;

	ret = __zbd_reset_zone(td, f, z);
	if (ret)
		return ret;

	pthread_mutex_lock(&f->zbd_info->mutex);
	zbd_write_zone_put(td, f, z);
	pthread_mutex_unlock(&f->zbd_info->mutex);
	return 0;
}

/**
 * zbd_finish_zone - finish the specified zone
 * @td: FIO thread data.
 * @f: FIO file for which to finish a zone
 * @z: Zone to finish.
 *
 * Finish the zone at @offset with open or close status.
 */
static int zbd_finish_zone(struct thread_data *td, struct fio_file *f,
			   struct fio_zone_info *z)
{
	uint64_t offset = z->start;
	uint64_t length = f->zbd_info->zone_size;
	int ret = 0;

	switch (f->zbd_info->model) {
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		if (td->io_ops && td->io_ops->finish_zone)
			ret = td->io_ops->finish_zone(td, f, offset, length);
		else
			ret = blkzoned_finish_zone(td, f, offset, length);
		break;
	default:
		break;
	}

	if (ret < 0) {
		td_verror(td, errno, "finish zone failed");
		log_err("%s: finish zone at sector %"PRIu64" failed (%d).\n",
			f->file_name, offset >> 9, errno);
	} else {
		z->wp = (z+1)->start;
	}

	return ret;
}

/**
 * zbd_reset_zones - Reset a range of zones.
 * @td: fio thread data.
 * @f: fio file for which to reset zones
 * @zb: first zone to reset.
 * @ze: first zone not to reset.
 *
 * Returns 0 upon success and 1 upon failure.
 */
static int zbd_reset_zones(struct thread_data *td, struct fio_file *f,
			   struct fio_zone_info *const zb,
			   struct fio_zone_info *const ze)
{
	struct fio_zone_info *z;
	const uint64_t min_bs = td->o.min_bs[DDIR_WRITE];
	int res = 0;

	if (fio_unlikely(0 == min_bs))
		return 1;

	dprint(FD_ZBD, "%s: examining zones %u .. %u\n",
	       f->file_name, zbd_zone_idx(f, zb), zbd_zone_idx(f, ze));

	for (z = zb; z < ze; z++) {
		if (!z->has_wp)
			continue;

		zone_lock(td, f, z);

		if (z->wp != z->start) {
			dprint(FD_ZBD, "%s: resetting zone %u\n",
			       f->file_name, zbd_zone_idx(f, z));
			if (zbd_reset_zone(td, f, z) < 0)
				res = 1;
		}

		zone_unlock(z);
	}

	return res;
}

/**
 * zbd_move_zone_wp - move the write pointer of a zone by writing the data in
 *               the specified buffer
 * @td: FIO thread data.
 * @f: FIO file for which to move write pointer
 * @z: Target zone to move the write pointer
 * @length: Length of the move
 * @buf: Buffer which holds the data to write
 *
 * Move the write pointer at the specified offset by writing the data
 * in the specified buffer.
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_move_zone_wp(struct thread_data *td, struct fio_file *f,
			    struct zbd_zone *z, uint64_t length,
			    const char *buf)
{
	int ret = 0;

	switch (f->zbd_info->model) {
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		if (td->io_ops && td->io_ops->move_zone_wp)
			ret = td->io_ops->move_zone_wp(td, f, z, length, buf);
		else
			ret = blkzoned_move_zone_wp(td, f, z, length, buf);
		break;
	default:
		break;
	}

	if (ret < 0) {
		td_verror(td, errno, "move wp failed");
		log_err("%s: moving wp for %"PRIu64" sectors at sector %"PRIu64" failed (%d).\n",
			f->file_name, length >> 9, z->wp >> 9, errno);
	}

	return ret;
}

/**
 * zbd_get_max_open_zones - Get the maximum number of open zones
 * @td: FIO thread data
 * @f: FIO file for which to get max open zones
 * @max_open_zones: Upon success, result will be stored here.
 *
 * A @max_open_zones value set to zero means no limit.
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				  unsigned int *max_open_zones)
{
	int ret;

	if (td->io_ops && td->io_ops->get_max_open_zones)
		ret = td->io_ops->get_max_open_zones(td, f, max_open_zones);
	else
		ret = blkzoned_get_max_open_zones(td, f, max_open_zones);
	if (ret < 0) {
		td_verror(td, errno, "get max open zones failed");
		log_err("%s: get max open zones failed (%d).\n",
			f->file_name, errno);
	}

	return ret;
}

/**
 * zbd_get_max_active_zones - Get the maximum number of active zones
 * @td: FIO thread data
 * @f: FIO file for which to get max active zones
 *
 * Returns max_active_zones limit value of the target file if it is available.
 * Otherwise return zero, which means no limit.
 */
static unsigned int zbd_get_max_active_zones(struct thread_data *td,
					     struct fio_file *f)
{
	unsigned int max_active_zones;
	int ret;

	if (td->io_ops && td->io_ops->get_max_active_zones)
		ret = td->io_ops->get_max_active_zones(td, f,
						       &max_active_zones);
	else
		ret = blkzoned_get_max_active_zones(td, f, &max_active_zones);
	if (ret < 0) {
		dprint(FD_ZBD, "%s: max_active_zones is not available\n",
		       f->file_name);
		return 0;
	}

	return max_active_zones;
}

/**
 * __zbd_write_zone_get - Add a zone to the array of write zones.
 * @td: fio thread data.
 * @f: fio file that has the write zones array to add.
 * @zone_idx: Index of the zone to add.
 *
 * Do same operation as @zbd_write_zone_get, except it adds the zone at
 * @zone_idx to write target zones array even when it does not have remainder
 * space to write one block.
 */
static bool __zbd_write_zone_get(struct thread_data *td,
				 const struct fio_file *f,
				 struct fio_zone_info *z)
{
	struct zoned_block_device_info *zbdi = f->zbd_info;
	uint32_t zone_idx = zbd_zone_idx(f, z);
	bool res = true;

	if (z->cond == ZBD_ZONE_COND_OFFLINE)
		return false;

	/*
	 * Skip full zones with data verification enabled because resetting a
	 * zone causes data loss and hence causes verification to fail.
	 */
	if (td->o.verify != VERIFY_NONE && zbd_zone_remainder(z) == 0)
		return false;

	/*
	 * zbdi->max_write_zones == 0 means that there is no limit on the
	 * maximum number of write target zones. In this case, do no track write
	 * target zones in zbdi->write_zones array.
	 */
	if (!zbdi->max_write_zones)
		return true;

	pthread_mutex_lock(&zbdi->mutex);

	if (z->write) {
		/*
		 * If the zone is going to be completely filled by writes
		 * already in-flight, handle it as a full zone instead of a
		 * write target zone.
		 */
		if (!zbd_zone_remainder(z))
			res = false;
		goto out;
	}

	res = false;
	/* Zero means no limit */
	if (td->o.job_max_open_zones > 0 &&
	    td->num_write_zones >= td->o.job_max_open_zones)
		goto out;
	if (zbdi->num_write_zones >= zbdi->max_write_zones)
		goto out;

	dprint(FD_ZBD, "%s: adding zone %u to write zone array\n",
	       f->file_name, zone_idx);

	zbdi->write_zones[zbdi->num_write_zones++] = zone_idx;
	td->num_write_zones++;
	z->write = 1;
	res = true;

out:
	pthread_mutex_unlock(&zbdi->mutex);
	return res;
}

/**
 * zbd_write_zone_get - Add a zone to the array of write zones.
 * @td: fio thread data.
 * @f: fio file that has the open zones to add.
 * @zone_idx: Index of the zone to add.
 *
 * Add a ZBD zone to write target zones array, if it is not yet added. Returns
 * true if either the zone was already added or if the zone was successfully
 * added to the array without exceeding the maximum number of write zones.
 * Returns false if the zone was not already added and addition of the zone
 * would cause the zone limit to be exceeded.
 */
static bool zbd_write_zone_get(struct thread_data *td, const struct fio_file *f,
			       struct fio_zone_info *z)
{
	const uint64_t min_bs = td->o.min_bs[DDIR_WRITE];

	/*
	 * Skip full zones with data verification enabled because resetting a
	 * zone causes data loss and hence causes verification to fail.
	 */
	if (td->o.verify != VERIFY_NONE && zbd_zone_full(f, z, min_bs))
		return false;

	return __zbd_write_zone_get(td, f, z);
}

/* Verify whether direct I/O is used for all host-managed zoned block drives. */
static bool zbd_using_direct_io(void)
{
	struct fio_file *f;
	int j;

	for_each_td(td) {
		if (td->o.odirect || !(td->o.td_ddir & TD_DDIR_WRITE))
			continue;
		for_each_file(td, f, j) {
			if (f->zbd_info && f->filetype == FIO_TYPE_BLOCK &&
			    f->zbd_info->model == ZBD_HOST_MANAGED)
				return false;
		}
	} end_for_each();

	return true;
}

/* Whether or not the I/O range for f includes one or more sequential zones */
static bool zbd_is_seq_job(const struct fio_file *f)
{
	uint32_t zone_idx, zone_idx_b, zone_idx_e;

	assert(f->zbd_info);

	if (f->io_size == 0)
		return false;

	zone_idx_b = zbd_offset_to_zone_idx(f, f->file_offset);
	zone_idx_e =
		zbd_offset_to_zone_idx(f, f->file_offset + f->io_size - 1);
	for (zone_idx = zone_idx_b; zone_idx <= zone_idx_e; zone_idx++)
		if (zbd_get_zone(f, zone_idx)->has_wp)
			return true;

	return false;
}

/*
 * Verify whether the file offset and size parameters are aligned with zone
 * boundaries. If the file offset is not aligned, align it down to the start of
 * the zone containing the start offset and align up the file io_size parameter.
 */
static bool zbd_zone_align_file_sizes(struct thread_data *td,
				      struct fio_file *f)
{
	const struct fio_zone_info *z;
	uint64_t new_offset, new_end;

	if (!f->zbd_info)
		return true;
	if (f->file_offset >= f->real_file_size)
		return true;
	if (!zbd_is_seq_job(f))
		return true;

	if (!td->o.zone_size) {
		td->o.zone_size = f->zbd_info->zone_size;
		if (!td->o.zone_size) {
			log_err("%s: invalid 0 zone size\n",
				f->file_name);
			return false;
		}
	} else if (td->o.zone_size != f->zbd_info->zone_size) {
		log_err("%s: zonesize %llu does not match the device zone size %"PRIu64".\n",
			f->file_name, td->o.zone_size,
			f->zbd_info->zone_size);
		return false;
	}

	if (td->o.zone_skip % td->o.zone_size) {
		log_err("%s: zoneskip %llu is not a multiple of the device zone size %llu.\n",
			f->file_name, td->o.zone_skip,
			td->o.zone_size);
		return false;
	}

	if (td->o.td_ddir == TD_DDIR_READ) {
		z = zbd_offset_to_zone(f, f->file_offset + f->io_size);
		new_end = z->start;
		if (f->file_offset + f->io_size > new_end) {
			log_info("%s: rounded io_size from %"PRIu64" to %"PRIu64"\n",
				 f->file_name, f->io_size,
				 new_end - f->file_offset);
			f->io_size = new_end - f->file_offset;
		}
		return true;
	}

	z = zbd_offset_to_zone(f, f->file_offset);
	if (f->file_offset != z->start) {
		new_offset = zbd_zone_end(z);
		if (new_offset >= f->file_offset + f->io_size) {
			log_info("%s: io_size must be at least one zone\n",
				 f->file_name);
			return false;
		}
		log_info("%s: rounded up offset from %"PRIu64" to %"PRIu64"\n",
			 f->file_name, f->file_offset,
			 new_offset);
		f->io_size -= (new_offset - f->file_offset);
		f->file_offset = new_offset;
	}

	z = zbd_offset_to_zone(f, f->file_offset + f->io_size);
	new_end = z->start;
	if (f->file_offset + f->io_size != new_end) {
		if (new_end <= f->file_offset) {
			log_info("%s: io_size must be at least one zone\n",
				 f->file_name);
			return false;
		}
		log_info("%s: rounded down io_size from %"PRIu64" to %"PRIu64"\n",
			 f->file_name, f->io_size,
			 new_end - f->file_offset);
		f->io_size = new_end - f->file_offset;
	}

	return true;
}

/*
 * Verify whether offset and size parameters are aligned with zone boundaries.
 */
static bool zbd_verify_sizes(void)
{
	struct fio_file *f;
	int j;

	for_each_td(td) {
		for_each_file(td, f, j) {
			if (!zbd_zone_align_file_sizes(td, f))
				return false;
		}
	} end_for_each();

	return true;
}

static bool zbd_verify_bs(void)
{
	struct fio_file *f;
	int j;

	for_each_td(td) {
		if (td_trim(td) &&
		    (td->o.min_bs[DDIR_TRIM] != td->o.max_bs[DDIR_TRIM] ||
		     td->o.bssplit_nr[DDIR_TRIM])) {
			log_info("bsrange and bssplit are not allowed for trim with zonemode=zbd\n");
			return false;
		}
		for_each_file(td, f, j) {
			uint64_t zone_size;

			if (!f->zbd_info)
				continue;

			zone_size = f->zbd_info->zone_size;
			if (td_trim(td) && td->o.bs[DDIR_TRIM] != zone_size) {
				log_info("%s: trim block size %llu is not the zone size %"PRIu64"\n",
					 f->file_name, td->o.bs[DDIR_TRIM],
					 zone_size);
				return false;
			}
		}
	} end_for_each();
	return true;
}

static int ilog2(uint64_t i)
{
	int log = -1;

	while (i) {
		i >>= 1;
		log++;
	}
	return log;
}

/*
 * Initialize f->zbd_info for devices that are not zoned block devices. This
 * allows to execute a ZBD workload against a non-ZBD device.
 */
static int init_zone_info(struct thread_data *td, struct fio_file *f)
{
	uint32_t nr_zones;
	struct fio_zone_info *p;
	uint64_t zone_size = td->o.zone_size;
	uint64_t zone_capacity = td->o.zone_capacity;
	struct zoned_block_device_info *zbd_info = NULL;
	int i;

	if (zone_size == 0) {
		log_err("%s: Specifying the zone size is mandatory for regular file/block device with --zonemode=zbd\n\n",
			f->file_name);
		return 1;
	}

	if (zone_size < 512) {
		log_err("%s: zone size must be at least 512 bytes for --zonemode=zbd\n\n",
			f->file_name);
		return 1;
	}

	if (zone_capacity == 0)
		zone_capacity = zone_size;

	if (zone_capacity > zone_size) {
		log_err("%s: job parameter zonecapacity %llu is larger than zone size %llu\n",
			f->file_name, td->o.zone_capacity, td->o.zone_size);
		return 1;
	}

	if (f->real_file_size < zone_size) {
		log_err("%s: file/device size %"PRIu64" is smaller than zone size %"PRIu64"\n",
			f->file_name, f->real_file_size, zone_size);
		return -EINVAL;
	}

	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;
	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	if (!zbd_info)
		return -ENOMEM;

	mutex_init_pshared(&zbd_info->mutex);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (i = 0; i < nr_zones; i++, p++) {
		mutex_init_pshared_with_type(&p->mutex,
					     PTHREAD_MUTEX_RECURSIVE);
		p->start = i * zone_size;
		p->wp = p->start;
		p->type = ZBD_ZONE_TYPE_SWR;
		p->cond = ZBD_ZONE_COND_EMPTY;
		p->capacity = zone_capacity;
		p->has_wp = 1;
	}
	/* a sentinel */
	p->start = nr_zones * zone_size;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : 0;
	f->zbd_info->nr_zones = nr_zones;
	return 0;
}

/*
 * Maximum number of zones to report in one operation.
 */
#define ZBD_REPORT_MAX_ZONES	8192U

/*
 * Parse the device zone report and store it in f->zbd_info. Must be called
 * only for devices that are zoned, namely those with a model != ZBD_NONE.
 */
static int parse_zone_info(struct thread_data *td, struct fio_file *f)
{
	int nr_zones, nrz;
	struct zbd_zone *zones, *z;
	struct fio_zone_info *p;
	uint64_t zone_size, offset, capacity;
	bool same_zone_cap = true;
	struct zoned_block_device_info *zbd_info = NULL;
	int i, j, ret = -ENOMEM;

	zones = calloc(ZBD_REPORT_MAX_ZONES, sizeof(struct zbd_zone));
	if (!zones)
		goto out;

	nrz = zbd_report_zones(td, f, 0, zones, ZBD_REPORT_MAX_ZONES);
	if (nrz < 0) {
		ret = nrz;
		log_info("fio: report zones (offset 0) failed for %s (%d).\n",
			 f->file_name, -ret);
		goto out;
	}

	zone_size = zones[0].len;
	capacity = zones[0].capacity;
	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;

	if (td->o.zone_size == 0) {
		td->o.zone_size = zone_size;
	} else if (td->o.zone_size != zone_size) {
		log_err("fio: %s job parameter zonesize %llu does not match disk zone size %"PRIu64".\n",
			f->file_name, td->o.zone_size, zone_size);
		ret = -EINVAL;
		goto out;
	}

	dprint(FD_ZBD, "Device %s has %d zones of size %"PRIu64" KB\n",
	       f->file_name, nr_zones, zone_size / 1024);

	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	if (!zbd_info)
		goto out;
	mutex_init_pshared(&zbd_info->mutex);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (offset = 0, j = 0; j < nr_zones;) {
		z = &zones[0];
		for (i = 0; i < nrz; i++, j++, z++, p++) {
			mutex_init_pshared_with_type(&p->mutex,
						     PTHREAD_MUTEX_RECURSIVE);
			p->start = z->start;
			p->capacity = z->capacity;
			if (capacity != z->capacity)
				same_zone_cap = false;

			switch (z->cond) {
			case ZBD_ZONE_COND_NOT_WP:
			case ZBD_ZONE_COND_FULL:
				p->wp = p->start + p->capacity;
				break;
			default:
				assert(z->start <= z->wp);
				assert(z->wp <= z->start + zone_size);
				p->wp = z->wp;
				break;
			}

			switch (z->type) {
			case ZBD_ZONE_TYPE_SWR:
				p->has_wp = 1;
				break;
			default:
				p->has_wp = 0;
			}
			p->type = z->type;
			p->cond = z->cond;

			if (j > 0 && p->start != p[-1].start + zone_size) {
				log_info("%s: invalid zone data [%d:%d]: %"PRIu64" + %"PRIu64" != %"PRIu64"\n",
					 f->file_name, j, i,
					 p[-1].start, zone_size, p->start);
				ret = -EINVAL;
				goto out;
			}
		}
		z--;
		offset = z->start + z->len;
		if (j >= nr_zones)
			break;

		nrz = zbd_report_zones(td, f, offset, zones,
				       min((uint32_t)(nr_zones - j),
					   ZBD_REPORT_MAX_ZONES));
		if (nrz < 0) {
			ret = nrz;
			log_info("fio: report zones (offset %"PRIu64") failed for %s (%d).\n",
				 offset, f->file_name, -ret);
			goto out;
		}
	}

	/* a sentinel */
	zbd_info->zone_info[nr_zones].start = offset;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : 0;
	f->zbd_info->nr_zones = nr_zones;
	f->zbd_info->max_active_zones = zbd_get_max_active_zones(td, f);

	if (same_zone_cap)
		dprint(FD_ZBD, "Zone capacity = %"PRIu64" KB\n",
		       capacity / 1024);

	zbd_info = NULL;
	ret = 0;

out:
	sfree(zbd_info);
	free(zones);
	return ret;
}

static int zbd_set_max_write_zones(struct thread_data *td, struct fio_file *f)
{
	struct zoned_block_device_info *zbd = f->zbd_info;
	unsigned int max_open_zones;
	int ret;

	if (zbd->model != ZBD_HOST_MANAGED || td->o.ignore_zone_limits) {
		/* Only host-managed devices have a max open limit */
		zbd->max_write_zones = td->o.max_open_zones;
		goto out;
	}

	/* If host-managed, get the max open limit */
	ret = zbd_get_max_open_zones(td, f, &max_open_zones);
	if (ret)
		return ret;

	if (!max_open_zones) {
		/* No device limit */
		zbd->max_write_zones = td->o.max_open_zones;
	} else if (!td->o.max_open_zones) {
		/* No user limit. Set limit to device limit */
		zbd->max_write_zones = max_open_zones;
	} else if (td->o.max_open_zones <= max_open_zones) {
		/* Both user limit and dev limit. User limit not too large */
		zbd->max_write_zones = td->o.max_open_zones;
	} else {
		/* Both user limit and dev limit. User limit too large */
		td_verror(td, EINVAL,
			  "Specified --max_open_zones is too large");
		log_err("Specified --max_open_zones (%d) is larger than max (%u)\n",
			td->o.max_open_zones, max_open_zones);
		return -EINVAL;
	}

out:
	/* Ensure that the limit is not larger than FIO's internal limit */
	if (zbd->max_write_zones > ZBD_MAX_WRITE_ZONES) {
		td_verror(td, EINVAL, "'max_open_zones' value is too large");
		log_err("'max_open_zones' value is larger than %u\n",
			ZBD_MAX_WRITE_ZONES);
		return -EINVAL;
	}

	dprint(FD_ZBD, "%s: using max write zones limit: %"PRIu32"\n",
	       f->file_name, zbd->max_write_zones);

	return 0;
}

/*
 * Allocate zone information and store it into f->zbd_info if zonemode=zbd.
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_create_zone_info(struct thread_data *td, struct fio_file *f)
{
	enum zbd_zoned_model zbd_model;
	int ret;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);

	ret = zbd_get_zoned_model(td, f, &zbd_model);
	if (ret)
		return ret;

	switch (zbd_model) {
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		ret = parse_zone_info(td, f);
		if (ret)
			return ret;
		break;
	case ZBD_NONE:
		ret = init_zone_info(td, f);
		if (ret)
			return ret;
		break;
	default:
		td_verror(td, EINVAL, "Unsupported zoned model");
		log_err("Unsupported zoned model\n");
		return -EINVAL;
	}

	assert(f->zbd_info);
	f->zbd_info->model = zbd_model;

	ret = zbd_set_max_write_zones(td, f);
	if (ret) {
		zbd_free_zone_info(f);
		return ret;
	}

	return 0;
}

void zbd_free_zone_info(struct fio_file *f)
{
	uint32_t refcount;

	assert(f->zbd_info);

	pthread_mutex_lock(&f->zbd_info->mutex);
	refcount = --f->zbd_info->refcount;
	pthread_mutex_unlock(&f->zbd_info->mutex);

	assert((int32_t)refcount >= 0);
	if (refcount == 0)
		sfree(f->zbd_info);
	f->zbd_info = NULL;
}

/*
 * Initialize f->zbd_info.
 *
 * Returns 0 upon success and a negative error code upon failure.
 *
 * Note: this function can only work correctly if it is called before the first
 * fio fork() call.
 */
static int zbd_init_zone_info(struct thread_data *td, struct fio_file *file)
{
	struct fio_file *f2;
	int j, ret;

	for_each_td(td2) {
		for_each_file(td2, f2, j) {
			if (td2 == td && f2 == file)
				continue;
			if (!f2->zbd_info ||
			    strcmp(f2->file_name, file->file_name) != 0)
				continue;
			file->zbd_info = f2->zbd_info;
			file->zbd_info->refcount++;
			return 0;
		}
	} end_for_each();

	ret = zbd_create_zone_info(td, file);
	if (ret < 0)
		td_verror(td, -ret, "zbd_create_zone_info() failed");

	return ret;
}

int zbd_init_files(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	for_each_file(td, f, i) {
		if (zbd_init_zone_info(td, f))
			return 1;
	}

	return 0;
}

void zbd_recalc_options_with_zone_granularity(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	for_each_file(td, f, i) {
		struct zoned_block_device_info *zbd = f->zbd_info;
		uint64_t zone_size;

		/* zonemode=strided doesn't get per-file zone size. */
		zone_size = zbd ? zbd->zone_size : td->o.zone_size;
		if (zone_size == 0)
			continue;

		if (td->o.size_nz > 0)
			td->o.size = td->o.size_nz * zone_size;
		if (td->o.io_size_nz > 0)
			td->o.io_size = td->o.io_size_nz * zone_size;
		if (td->o.start_offset_nz > 0)
			td->o.start_offset = td->o.start_offset_nz * zone_size;
		if (td->o.offset_increment_nz > 0)
			td->o.offset_increment =
				td->o.offset_increment_nz * zone_size;
		if (td->o.zone_skip_nz > 0)
			td->o.zone_skip = td->o.zone_skip_nz * zone_size;
	}
}

static uint64_t zbd_verify_and_set_vdb(struct thread_data *td,
				       const struct fio_file *f)
{
	struct fio_zone_info *zb, *ze, *z;
	uint64_t wp_vdb = 0;
	struct zoned_block_device_info *zbdi = f->zbd_info;

	assert(td->runstate < TD_RUNNING);
	assert(zbdi);

	if (!accounting_vdb(td, f))
		return 0;

	/*
	 * Ensure that the I/O range includes one or more sequential zones so
	 * that f->min_zone and f->max_zone have different values.
	 */
	if (!zbd_is_seq_job(f))
		return 0;

	if (zbdi->write_min_zone != zbdi->write_max_zone) {
		if (zbdi->write_min_zone != f->min_zone ||
		    zbdi->write_max_zone != f->max_zone) {
			td_verror(td, EINVAL,
				  "multi-jobs with different write ranges are "
				  "not supported with zone_reset_threshold");
			log_err("multi-jobs with different write ranges are "
				"not supported with zone_reset_threshold\n");
		}
		return 0;
	}

	zbdi->write_min_zone = f->min_zone;
	zbdi->write_max_zone = f->max_zone;

	zb = zbd_get_zone(f, f->min_zone);
	ze = zbd_get_zone(f, f->max_zone);
	for (z = zb; z < ze; z++)
		if (z->has_wp)
			wp_vdb += z->wp - z->start;

	zbdi->wp_valid_data_bytes = wp_vdb;

	return wp_vdb;
}

int zbd_setup_files(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	if (!zbd_using_direct_io()) {
		log_err("Using direct I/O is mandatory for writing to ZBD drives\n\n");
		return 1;
	}

	if (!zbd_verify_sizes())
		return 1;

	if (!zbd_verify_bs())
		return 1;

	if (td->o.recover_zbd_write_error && td_write(td)) {
		if (!td->o.continue_on_error) {
			log_err("recover_zbd_write_error works only when continue_on_error is set\n");
			return 1;
		}
		if (td->o.verify != VERIFY_NONE &&
		    !td_ioengine_flagged(td, FIO_SYNCIO)) {
			log_err("recover_zbd_write_error for async IO engines does not support verify\n");
			return 1;
		}
	}

	if (td->o.experimental_verify) {
		log_err("zonemode=zbd does not support experimental verify\n");
		return 1;
	}

	/* Enable zone reset stat report for write and trim workloads */
	if (td_write(td) || td_trim(td))
		td->ts.count_zone_resets = 1;

	for_each_file(td, f, i) {
		struct zoned_block_device_info *zbd = f->zbd_info;
		struct fio_zone_info *z;
		int zi;
		uint64_t vdb;

		assert(zbd);

		f->min_zone = zbd_offset_to_zone_idx(f, f->file_offset);
		f->max_zone =
			zbd_offset_to_zone_idx(f, f->file_offset + f->io_size);

		vdb = zbd_verify_and_set_vdb(td, f);

		dprint(FD_ZBD, "%s(%s): valid data bytes = %" PRIu64 "\n",
		       __func__, f->file_name, vdb);

		/*
		 * When all zones in the I/O range are conventional, io_size
		 * can be smaller than zone size, making min_zone the same
		 * as max_zone. This is why the assert below needs to be made
		 * conditional.
		 */
		if (zbd_is_seq_job(f))
			assert(f->min_zone < f->max_zone);

		if (td->o.max_open_zones > 0 &&
		    zbd->max_write_zones != td->o.max_open_zones) {
			log_err("Different 'max_open_zones' values\n");
			return 1;
		}

		/*
		 * If this job does not do write operations, skip open zone
		 * condition check.
		 */
		if (!td_write(td)) {
			if (td->o.job_max_open_zones)
				log_info("'job_max_open_zones' is valid only for write jobs\n");
			continue;
		}

		/*
		 * The per job max open zones limit cannot be used without a
		 * global max open zones limit. (As the tracking of open zones
		 * is disabled when there is no global max open zones limit.)
		 */
		if (td->o.job_max_open_zones && !zbd->max_write_zones) {
			log_err("'job_max_open_zones' cannot be used without a global open zones limit\n");
			return 1;
		}

		/*
		 * zbd->max_write_zones is the global limit shared for all jobs
		 * that target the same zoned block device. Force sync the per
		 * thread global limit with the actual global limit. (The real
		 * per thread/job limit is stored in td->o.job_max_open_zones).
		 */
		td->o.max_open_zones = zbd->max_write_zones;

		for (zi = f->min_zone; zi < f->max_zone; zi++) {
			z = &zbd->zone_info[zi];
			if (z->cond != ZBD_ZONE_COND_IMP_OPEN &&
			    z->cond != ZBD_ZONE_COND_EXP_OPEN &&
			    z->cond != ZBD_ZONE_COND_CLOSED)
				continue;
			if (!zbd->max_active_zones &&
			    z->cond == ZBD_ZONE_COND_CLOSED)
				continue;
			if (__zbd_write_zone_get(td, f, z))
				continue;
			/*
			 * If the number of open zones exceeds specified limits,
			 * error out.
			 */
			log_err("Number of open zones exceeds max_open_zones limit\n");
			return 1;
		}
	}

	return 0;
}

/*
 * Reset zbd_info.write_cnt, the counter that counts down towards the next
 * zone reset.
 */
static void _zbd_reset_write_cnt(const struct thread_data *td,
				 const struct fio_file *f)
{
	assert(0 <= td->o.zrf.u.f && td->o.zrf.u.f <= 1);

	f->zbd_info->write_cnt = td->o.zrf.u.f ?
		min(1.0 / td->o.zrf.u.f, 0.0 + UINT_MAX) : UINT_MAX;
}

static void zbd_reset_write_cnt(const struct thread_data *td,
				const struct fio_file *f)
{
	pthread_mutex_lock(&f->zbd_info->mutex);
	_zbd_reset_write_cnt(td, f);
	pthread_mutex_unlock(&f->zbd_info->mutex);
}

static bool zbd_dec_and_reset_write_cnt(const struct thread_data *td,
					const struct fio_file *f)
{
	uint32_t write_cnt = 0;

	pthread_mutex_lock(&f->zbd_info->mutex);
	assert(f->zbd_info->write_cnt);
	if (f->zbd_info->write_cnt)
		write_cnt = --f->zbd_info->write_cnt;
	if (write_cnt == 0)
		_zbd_reset_write_cnt(td, f);
	pthread_mutex_unlock(&f->zbd_info->mutex);

	return write_cnt == 0;
}

void zbd_file_reset(struct thread_data *td, struct fio_file *f)
{
	struct fio_zone_info *zb, *ze;
	bool verify_data_left = false;

	if (!f->zbd_info || !td_write(td))
		return;

	zb = zbd_get_zone(f, f->min_zone);
	ze = zbd_get_zone(f, f->max_zone);

	/*
	 * If data verification is enabled reset the affected zones before
	 * writing any data to avoid that a zone reset has to be issued while
	 * writing data, which causes data loss.
	 */
	if (td->o.verify != VERIFY_NONE) {
		verify_data_left = td->runstate == TD_VERIFYING ||
			td->io_hist_len || td->verify_batch;
		if (!verify_data_left)
			zbd_reset_zones(td, f, zb, ze);
	}

	zbd_reset_write_cnt(td, f);
}

/* Return random zone index for one of the write target zones. */
static uint32_t pick_random_zone_idx(const struct fio_file *f,
				     const struct io_u *io_u)
{
	return (io_u->offset - f->file_offset) *
		f->zbd_info->num_write_zones / f->io_size;
}

/*
 * Randomly choose a zone in the array of write zones and in the range for the
 * file f. If such a zone is found, return its index in f->zbd_info->zone_info[]
 * using @zone_idx, and return true. Otherwise, return false.
 *
 * Caller must hold f->zbd_info->mutex.
 */
static bool zbd_pick_write_zone(const struct fio_file* f,
				const struct io_u *io_u, uint32_t *zone_idx)
{
	struct zoned_block_device_info *zbdi = f->zbd_info;
	uint32_t write_zone_idx;
	uint32_t cur_zone_idx;
	int i;

	/*
	 * An array of write target zones is per-device, shared across all jobs.
	 * Start with quasi-random candidate zone. Ignore zones which do not
	 * belong to offset/size range of the current job.
	 */
	write_zone_idx = pick_random_zone_idx(f, io_u);
	assert(!write_zone_idx || write_zone_idx < zbdi->num_write_zones);

	for (i = 0; i < zbdi->num_write_zones; i++) {
		if (write_zone_idx >= zbdi->num_write_zones)
			write_zone_idx = 0;
		cur_zone_idx = zbdi->write_zones[write_zone_idx];
		if (f->min_zone <= cur_zone_idx && cur_zone_idx < f->max_zone) {
			*zone_idx = cur_zone_idx;
			return true;
		}
		write_zone_idx++;
	}

	return false;
}

static bool any_io_in_flight(void)
{
	for_each_td(td) {
		if (td->io_u_in_flight)
			return true;
	} end_for_each();

	return false;
}

/**
 * zbd_convert_to_write_zone - Convert the target zone of an io_u to a writable zone
 * @td: The fio thread data
 * @io_u: The I/O unit that targets the zone to convert
 * @zb: The zone selected at the beginning of the function call. The caller must
 *      hold zb->mutex.
 *
 * Modify the offset of an I/O unit that does not refer to a zone such that
 * in write target zones array. Add a zone to or remove a zone from the array if
 * necessary. The write target zone is searched across sequential zones.
 * This algorithm can only work correctly if all write pointers are
 * a multiple of the fio block size. The caller must not hold
 * f->zbd_info->mutex. Returns with z->mutex held upon success.
 */
static struct fio_zone_info *zbd_convert_to_write_zone(struct thread_data *td,
						       struct io_u *io_u,
						       struct fio_zone_info *zb)
{
	const uint64_t min_bs = td->o.min_bs[io_u->ddir];
	struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbdi = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx, new_zone_idx;
	int i;
	bool wait_zone_write;
	bool in_flight;
	bool should_retry = true;
	bool need_zone_finish;

	assert(is_valid_offset(f, io_u->offset));

	if (zbd_zone_remainder(zb) > 0 && zbd_zone_remainder(zb) < min_bs) {
		pthread_mutex_lock(&f->zbd_info->mutex);
		zbd_write_zone_put(td, f, zb);
		pthread_mutex_unlock(&f->zbd_info->mutex);
		dprint(FD_ZBD, "%s: finish zone %d\n",
		       f->file_name, zbd_zone_idx(f, zb));
		io_u_quiesce(td);
		zbd_finish_zone(td, f, zb);
		zone_unlock(zb);

		if (zbd_zone_idx(f, zb) + 1 >= f->max_zone && !td_random(td))
			return NULL;

		/* Find the next write pointer zone */
		do {
			zb++;
			if (zbd_zone_idx(f, zb) >= f->max_zone)
				zb = zbd_get_zone(f, f->min_zone);
		} while (!zb->has_wp);

		zone_lock(td, f, zb);
	}

	if (zbd_write_zone_get(td, f, zb))
		return zb;

	zone_unlock(zb);

	if (zbdi->max_write_zones || td->o.job_max_open_zones) {
		/*
		 * This statement accesses zbdi->write_zones[] on purpose
		 * without locking.
		 */
		zone_idx = zbdi->write_zones[pick_random_zone_idx(f, io_u)];
	} else {
		zone_idx = zbd_offset_to_zone_idx(f, io_u->offset);
	}
	if (zone_idx < f->min_zone)
		zone_idx = f->min_zone;
	else if (zone_idx >= f->max_zone)
		zone_idx = f->max_zone - 1;

	dprint(FD_ZBD,
	       "%s(%s): starting from zone %d (offset %lld, buflen %lld)\n",
	       __func__, f->file_name, zone_idx, io_u->offset, io_u->buflen);

	/*
	 * Since z->mutex is the outer lock and zbdi->mutex the inner
	 * lock it can happen that the state of the zone with index zone_idx
	 * has changed after 'z' has been assigned and before zbdi->mutex
	 * has been obtained. Hence the loop.
	 */
	for (;;) {
		z = zbd_get_zone(f, zone_idx);
		if (z->has_wp)
			zone_lock(td, f, z);

		pthread_mutex_lock(&zbdi->mutex);

		if (z->has_wp) {
			if (z->cond != ZBD_ZONE_COND_OFFLINE &&
			    zbdi->max_write_zones == 0 &&
			    td->o.job_max_open_zones == 0)
				goto examine_zone;
			if (zbdi->num_write_zones == 0) {
				dprint(FD_ZBD, "%s(%s): no zone is write target\n",
				       __func__, f->file_name);
				goto choose_other_zone;
			}
		}

		if (!zbd_pick_write_zone(f, io_u, &new_zone_idx)) {
			dprint(FD_ZBD, "%s(%s): no candidate zone\n",
			       __func__, f->file_name);
			pthread_mutex_unlock(&zbdi->mutex);
			if (z->has_wp)
				zone_unlock(z);
			return NULL;
		}

		if (new_zone_idx == zone_idx)
			break;
		zone_idx = new_zone_idx;

		pthread_mutex_unlock(&zbdi->mutex);

		if (z->has_wp)
			zone_unlock(z);
	}

	/* Both z->mutex and zbdi->mutex are held. */

examine_zone:
	if (zbd_zone_remainder(z) >= min_bs) {
		pthread_mutex_unlock(&zbdi->mutex);
		goto out;
	}

choose_other_zone:
	/* Check if number of write target zones reaches one of limits. */
	wait_zone_write =
		zbdi->num_write_zones == f->max_zone - f->min_zone ||
		(zbdi->max_write_zones &&
		 zbdi->num_write_zones == zbdi->max_write_zones) ||
		(td->o.job_max_open_zones &&
		 td->num_write_zones == td->o.job_max_open_zones);

	pthread_mutex_unlock(&zbdi->mutex);

	/* Only z->mutex is held. */

	/*
	 * When number of write target zones reaches to one of limits, wait for
	 * zone write completion to one of them before trying a new zone.
	 */
	if (wait_zone_write) {
		dprint(FD_ZBD,
		       "%s(%s): quiesce to remove a zone from write target zones array\n",
		       __func__, f->file_name);
		io_u_quiesce(td);
	}

retry:
	/* Zone 'z' is full, so try to choose a new zone. */
	for (i = f->io_size / zbdi->zone_size; i > 0; i--) {
		zone_idx++;
		if (z->has_wp)
			zone_unlock(z);
		z++;
		if (!is_valid_offset(f, z->start)) {
			/* Wrap-around. */
			zone_idx = f->min_zone;
			z = zbd_get_zone(f, zone_idx);
		}
		assert(is_valid_offset(f, z->start));
		if (!z->has_wp)
			continue;
		zone_lock(td, f, z);
		if (z->write)
			continue;
		if (zbd_write_zone_get(td, f, z))
			goto out;
	}

	/* Only z->mutex is held. */

	/* Check whether the write fits in any of the write target zones. */
	pthread_mutex_lock(&zbdi->mutex);
	need_zone_finish = true;
	for (i = 0; i < zbdi->num_write_zones; i++) {
		zone_idx = zbdi->write_zones[i];
		if (zone_idx < f->min_zone || zone_idx >= f->max_zone)
			continue;
		pthread_mutex_unlock(&zbdi->mutex);
		zone_unlock(z);

		z = zbd_get_zone(f, zone_idx);

		zone_lock(td, f, z);
		if (zbd_zone_remainder(z) >= min_bs) {
			need_zone_finish = false;
			goto out;
		}
		pthread_mutex_lock(&zbdi->mutex);
	}

	/*
	 * When any I/O is in-flight or when all I/Os in-flight get completed,
	 * the I/Os might have removed zones from the write target array then
	 * retry the steps to choose a zone. Before retry, call io_u_quiesce()
	 * to complete in-flight writes.
	 */
	in_flight = any_io_in_flight();
	if (in_flight || should_retry) {
		dprint(FD_ZBD,
		       "%s(%s): wait zone write and retry write target zone selection\n",
		       __func__, f->file_name);
		should_retry = in_flight;
		pthread_mutex_unlock(&zbdi->mutex);
		zone_unlock(z);
		io_u_quiesce(td);
		zone_lock(td, f, z);
		goto retry;
	}

	if (td_random(td) && td->o.verify == VERIFY_NONE && need_zone_finish)
		/*
		 * If all open zones have remainder smaller than the block size
		 * for random write jobs, choose one of the write target zones
		 * and finish it. When verify is enabled, skip this zone finish
		 * operation to avoid verify data corruption by overwrite to the
		 * zone.
		 */
		if (zbd_pick_write_zone(f, io_u, &zone_idx)) {
			pthread_mutex_unlock(&zbdi->mutex);
			zone_unlock(z);
			z = zbd_get_zone(f, zone_idx);
			zone_lock(td, f, z);
			io_u_quiesce(td);
			dprint(FD_ZBD, "%s(%s): All write target zones have remainder smaller than block size. Choose zone %d and finish.\n",
			       __func__, f->file_name, zone_idx);
			zbd_finish_zone(td, f, z);
			goto out;
		}

	pthread_mutex_unlock(&zbdi->mutex);

	zone_unlock(z);

	dprint(FD_ZBD, "%s(%s): did not choose another write zone\n",
	       __func__, f->file_name);

	return NULL;

out:
	dprint(FD_ZBD, "%s(%s): returning zone %d\n",
	       __func__, f->file_name, zone_idx);

	io_u->offset = z->start;
	assert(z->has_wp);
	assert(z->cond != ZBD_ZONE_COND_OFFLINE);

	return z;
}

/*
 * Find another zone which has @min_bytes of readable data. Search in zones
 * @zb + 1 .. @zl. For random workload, also search in zones @zb - 1 .. @zf.
 *
 * Either returns NULL or returns a zone pointer. When the zone has write
 * pointer, hold the mutex for the zone.
 */
static struct fio_zone_info *
zbd_find_zone(struct thread_data *td, struct io_u *io_u, uint64_t min_bytes,
	      struct fio_zone_info *zb, struct fio_zone_info *zl)
{
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z1, *z2;
	const struct fio_zone_info *const zf = zbd_get_zone(f, f->min_zone);

	/*
	 * Skip to the next non-empty zone in case of sequential I/O and to
	 * the nearest non-empty zone in case of random I/O.
	 */
	for (z1 = zb + 1, z2 = zb - 1; z1 < zl || z2 >= zf; z1++, z2--) {
		if (z1 < zl && z1->cond != ZBD_ZONE_COND_OFFLINE) {
			if (z1->has_wp)
				zone_lock(td, f, z1);
			if (z1->start + min_bytes <= z1->wp)
				return z1;
			if (z1->has_wp)
				zone_unlock(z1);
		} else if (!td_random(td)) {
			break;
		}

		if (td_random(td) && z2 >= zf &&
		    z2->cond != ZBD_ZONE_COND_OFFLINE) {
			if (z2->has_wp)
				zone_lock(td, f, z2);
			if (z2->start + min_bytes <= z2->wp)
				return z2;
			if (z2->has_wp)
				zone_unlock(z2);
		}
	}

	dprint(FD_ZBD,
	       "%s: no zone has %"PRIu64" bytes of readable data\n",
	       f->file_name, min_bytes);

	return NULL;
}

/**
 * zbd_end_zone_io - update zone status at command completion
 * @io_u: I/O unit
 * @z: zone info pointer
 *
 * If the write command made the zone full, remove it from the write target
 * zones array.
 *
 * The caller must hold z->mutex.
 */
static void zbd_end_zone_io(struct thread_data *td, const struct io_u *io_u,
			    struct fio_zone_info *z)
{
	const struct fio_file *f = io_u->file;

	if (io_u->ddir == DDIR_WRITE &&
	    io_u->offset + io_u->buflen >= zbd_zone_capacity_end(z)) {
		pthread_mutex_lock(&f->zbd_info->mutex);
		zbd_write_zone_put(td, f, z);
		pthread_mutex_unlock(&f->zbd_info->mutex);
	}
}

/**
 * zbd_queue_io - update the write pointer of a sequential zone
 * @io_u: I/O unit
 * @success: Whether or not the I/O unit has been queued successfully
 * @q: queueing status (busy, completed or queued).
 *
 * For write and trim operations, update the write pointer of the I/O unit
 * target zone.
 */
static void zbd_queue_io(struct thread_data *td, struct io_u *io_u, int *q)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	bool success = io_u->error == 0;
	struct fio_zone_info *z;
	uint64_t zone_end;

	assert(zbd_info);

	z = zbd_offset_to_zone(f, io_u->offset);
	assert(z->has_wp);

	if (!success && td->o.recover_zbd_write_error &&
	    io_u->ddir == DDIR_WRITE && td_ioengine_flagged(td, FIO_SYNCIO) &&
	    *q == FIO_Q_COMPLETED) {
		zbd_recover_write_error(td, io_u);
		if (!io_u->error)
			success = true;
	}

	if (!success)
		goto unlock;

	dprint(FD_ZBD,
	       "%s: queued I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zbd_zone_idx(f, z));

	switch (io_u->ddir) {
	case DDIR_WRITE:
		zone_end = min((uint64_t)(io_u->offset + io_u->buflen),
			       zbd_zone_capacity_end(z));

		/*
		 * z->wp > zone_end means that one or more I/O errors
		 * have occurred.
		 */
		if (accounting_vdb(td, f) && z->wp <= zone_end) {
			pthread_mutex_lock(&zbd_info->mutex);
			zbd_info->wp_valid_data_bytes += zone_end - z->wp;
			pthread_mutex_unlock(&zbd_info->mutex);
		}
		z->wp = zone_end;
		break;
	default:
		break;
	}

	if (*q == FIO_Q_COMPLETED && !io_u->error)
		zbd_end_zone_io(td, io_u, z);

unlock:
	if (!success || *q != FIO_Q_QUEUED) {
		if (io_u->ddir == DDIR_WRITE) {
			z->writes_in_flight--;
			if (z->writes_in_flight == 0 && z->fixing_zone_wp) {
				dprint(FD_ZBD, "%s: Fixed write pointer of the zone %u\n",
				       f->file_name, zbd_zone_idx(f, z));
				z->fixing_zone_wp = 0;
			}
		}
		/* BUSY or COMPLETED: unlock the zone */
		zone_unlock(z);
		io_u->zbd_put_io = NULL;
	}
}

/**
 * zbd_put_io - Unlock an I/O unit target zone lock
 * @io_u: I/O unit
 */
static void zbd_put_io(struct thread_data *td, const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z;

	assert(f->zbd_info);

	z = zbd_offset_to_zone(f, io_u->offset);
	assert(z->has_wp);

	dprint(FD_ZBD,
	       "%s: terminate I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zbd_zone_idx(f, z));

	zbd_end_zone_io(td, io_u, z);

	if (io_u->ddir == DDIR_WRITE) {
		z->writes_in_flight--;
		if (z->writes_in_flight == 0 && z->fixing_zone_wp) {
			z->fixing_zone_wp = 0;
			dprint(FD_ZBD, "%s: Fixed write pointer of the zone %u\n",
			       f->file_name, zbd_zone_idx(f, z));
		}
	}

	zone_unlock(z);
}

/*
 * Windows and MacOS do not define this.
 */
#ifndef EREMOTEIO
#define EREMOTEIO	121	/* POSIX value */
#endif

bool zbd_unaligned_write(int error_code)
{
	switch (error_code) {
	case EIO:
	case EREMOTEIO:
		return true;
	}
	return false;
}

/**
 * setup_zbd_zone_mode - handle zoneskip as necessary for ZBD drives
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 *
 * For sequential workloads, change the file offset to skip zoneskip bytes when
 * no more IO can be performed in the current zone.
 * - For read workloads, zoneskip is applied when the io has reached the end of
 *   the zone or the zone write position (when td->o.read_beyond_wp is false).
 * - For write workloads, zoneskip is applied when the zone is full.
 * This applies only to read and write operations.
 */
void setup_zbd_zone_mode(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	enum fio_ddir ddir = io_u->ddir;
	struct fio_zone_info *z;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);
	assert(td->o.zone_size);
	assert(f->zbd_info);

	z = zbd_offset_to_zone(f, f->last_pos[ddir]);

	/*
	 * When the zone capacity is smaller than the zone size and the I/O is
	 * sequential write, skip to zone end if the latest position is at the
	 * zone capacity limit.
	 */
	if (z->capacity < f->zbd_info->zone_size &&
	    !td_random(td) && ddir == DDIR_WRITE &&
	    f->last_pos[ddir] >= zbd_zone_capacity_end(z)) {
		dprint(FD_ZBD,
		       "%s: Jump from zone capacity limit to zone end:"
		       " (%"PRIu64" -> %"PRIu64") for zone %u (%"PRIu64")\n",
		       f->file_name, f->last_pos[ddir],
		       zbd_zone_end(z), zbd_zone_idx(f, z), z->capacity);
		td->io_skip_bytes += zbd_zone_end(z) - f->last_pos[ddir];
		f->last_pos[ddir] = zbd_zone_end(z);
	}

	/*
	 * zone_skip is valid only for sequential workloads.
	 */
	if (td_random(td) || !td->o.zone_skip)
		return;

	/*
	 * It is time to switch to a new zone if:
	 * - zone_bytes == zone_size bytes have already been accessed
	 * - The last position reached the end of the current zone.
	 * - For reads with td->o.read_beyond_wp == false, the last position
	 *   reached the zone write pointer.
	 */
	if (td->zone_bytes >= td->o.zone_size ||
	    f->last_pos[ddir] >= zbd_zone_end(z) ||
	    (ddir == DDIR_READ &&
	     (!td->o.read_beyond_wp) && f->last_pos[ddir] >= z->wp)) {
		/*
		 * Skip zones.
		 */
		td->zone_bytes = 0;
		f->file_offset += td->o.zone_size + td->o.zone_skip;

		/*
		 * Wrap from the beginning, if we exceed the file size
		 */
		if (f->file_offset >= f->real_file_size)
			f->file_offset = get_start_offset(td, f);

		f->last_pos[ddir] = f->file_offset;
		td->io_skip_bytes += td->o.zone_skip;
	}
}

/**
 * zbd_adjust_ddir - Adjust an I/O direction for zonemode=zbd.
 *
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 * @ddir: I/O direction before adjustment.
 *
 * Return adjusted I/O direction.
 */
enum fio_ddir zbd_adjust_ddir(struct thread_data *td, struct io_u *io_u,
			      enum fio_ddir ddir)
{
	/*
	 * In case read direction is chosen for the first random I/O, fio with
	 * zonemode=zbd stops because no data can be read from zoned block
	 * devices with all empty zones. Overwrite the first I/O direction as
	 * write to make sure data to read exists.
	 */
	assert(io_u->file->zbd_info);
	if (ddir != DDIR_READ || !td_rw(td))
		return ddir;

	if (io_u->file->last_start[DDIR_WRITE] != -1ULL ||
	    td->o.read_beyond_wp || td->o.rwmix[DDIR_WRITE] == 0)
		return DDIR_READ;

	return DDIR_WRITE;
}

/**
 * zbd_adjust_block - adjust the offset and length as necessary for ZBD drives
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 *
 * Locking strategy: returns with z->mutex locked if and only if z refers
 * to a sequential zone and if io_u_accept is returned. z is the zone that
 * corresponds to io_u->offset at the end of this function.
 */
enum io_u_action zbd_adjust_block(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbdi = f->zbd_info;
	struct fio_zone_info *zb, *zl, *orig_zb;
	uint32_t orig_len = io_u->buflen;
	uint64_t min_bs = td->o.min_bs[io_u->ddir];
	uint64_t new_len;
	int64_t range;

	assert(zbdi);
	assert(min_bs);
	assert(is_valid_offset(f, io_u->offset));
	assert(io_u->buflen);

	zb = zbd_offset_to_zone(f, io_u->offset);
	orig_zb = zb;

	if (!zb->has_wp) {
		/* Accept non-write I/Os for conventional zones. */
		if (io_u->ddir != DDIR_WRITE)
			return io_u_accept;

		/*
		 * Make sure that writes to conventional zones
		 * don't cross over to any sequential zones.
		 */
		if (!(zb + 1)->has_wp ||
		    io_u->offset + io_u->buflen <= (zb + 1)->start)
			return io_u_accept;

		if (io_u->offset + min_bs > (zb + 1)->start) {
			dprint(FD_IO,
			       "%s: off=%llu + min_bs=%"PRIu64" > next zone %"PRIu64"\n",
			       f->file_name, io_u->offset,
			       min_bs, (zb + 1)->start);
			io_u->offset =
				zb->start + (zb + 1)->start - io_u->offset;
			new_len = min(io_u->buflen,
				      (zb + 1)->start - io_u->offset);
		} else {
			new_len = (zb + 1)->start - io_u->offset;
		}

		io_u->buflen = new_len / min_bs * min_bs;

		return io_u_accept;
	}

	/*
	 * Accept the I/O offset for reads if reading beyond the write pointer
	 * is enabled.
	 */
	if (zb->cond != ZBD_ZONE_COND_OFFLINE &&
	    io_u->ddir == DDIR_READ && td->o.read_beyond_wp)
		return io_u_accept;

retry_lock:
	zone_lock(td, f, zb);

	if (!td_ioengine_flagged(td, FIO_SYNCIO) && zb->fixing_zone_wp) {
		zone_unlock(zb);
		io_u_quiesce(td);
		goto retry_lock;
	}

	switch (io_u->ddir) {
	case DDIR_READ:
		if (td->runstate == TD_VERIFYING && td_write(td))
			goto accept;

		/*
		 * Check that there is enough written data in the zone to do an
		 * I/O of at least min_bs B. If there isn't, find a new zone for
		 * the I/O.
		 */
		range = zb->cond != ZBD_ZONE_COND_OFFLINE ?
			zb->wp - zb->start : 0;
		if (range < min_bs ||
		    ((!td_random(td)) && (io_u->offset + min_bs > zb->wp))) {
			zone_unlock(zb);
			zl = zbd_get_zone(f, f->max_zone);
			zb = zbd_find_zone(td, io_u, min_bs, zb, zl);
			if (!zb) {
				dprint(FD_ZBD,
				       "%s: zbd_find_zone(%lld, %llu) failed\n",
				       f->file_name, io_u->offset,
				       io_u->buflen);
				goto eof;
			}
			/*
			 * zbd_find_zone() returned a zone with a range of at
			 * least min_bs.
			 */
			range = zb->wp - zb->start;
			assert(range >= min_bs);

			if (!td_random(td))
				io_u->offset = zb->start;
		}

		/*
		 * Make sure the I/O is within the zone valid data range while
		 * maximizing the I/O size and preserving randomness.
		 */
		if (range <= io_u->buflen)
			io_u->offset = zb->start;
		else if (td_random(td))
			io_u->offset = zb->start +
				((io_u->offset - orig_zb->start) %
				 (range - io_u->buflen)) / min_bs * min_bs;

		/*
		 * When zbd_find_zone() returns a conventional zone,
		 * we can simply accept the new i/o offset here.
		 */
		if (!zb->has_wp)
			return io_u_accept;

		/*
		 * Make sure the I/O does not cross over the zone wp position.
		 */
		new_len = min((unsigned long long)io_u->buflen,
			      (unsigned long long)(zb->wp - io_u->offset));
		new_len = new_len / min_bs * min_bs;
		if (new_len < io_u->buflen) {
			io_u->buflen = new_len;
			dprint(FD_IO, "Changed length from %u into %llu\n",
			       orig_len, io_u->buflen);
		}

		assert(zb->start <= io_u->offset);
		assert(io_u->offset + io_u->buflen <= zb->wp);

		goto accept;

	case DDIR_WRITE:
		if (io_u->buflen > zbdi->zone_size) {
			td_verror(td, EINVAL, "I/O buflen exceeds zone size");
			dprint(FD_IO,
			       "%s: I/O buflen %llu exceeds zone size %"PRIu64"\n",
			       f->file_name, io_u->buflen, zbdi->zone_size);
			goto eof;
		}

retry:
		zb = zbd_convert_to_write_zone(td, io_u, zb);
		if (!zb) {
			dprint(FD_IO, "%s: can't convert to write target zone",
			       f->file_name);
			goto eof;
		}

		if (zbd_zone_remainder(zb) > 0 &&
		    zbd_zone_remainder(zb) < min_bs)
			goto retry;

		/* Check whether the zone reset threshold has been exceeded */
		if (td->o.zrf.u.f) {
			if (zbdi->wp_valid_data_bytes >=
			    f->io_size * td->o.zrt.u.f &&
			    zbd_dec_and_reset_write_cnt(td, f))
				zb->reset_zone = 1;
		}

		/* Reset the zone pointer if necessary */
		if (zb->reset_zone || zbd_zone_full(f, zb, min_bs)) {
			if (td->o.verify != VERIFY_NONE) {
				/*
				 * Unset io-u->file to tell get_next_verify()
				 * that this IO is not requeue.
				 */
				io_u->file = NULL;
				if (!get_next_verify(td, io_u)) {
					zone_unlock(zb);
					return io_u_accept;
				}
				io_u->file = f;
			}

			/*
			 * Since previous write requests may have been submitted
			 * asynchronously and since we will submit the zone
			 * reset synchronously, wait until previously submitted
			 * write requests have completed before issuing a
			 * zone reset.
			 */
			io_u_quiesce(td);
			zb->reset_zone = 0;
			if (__zbd_reset_zone(td, f, zb) < 0)
				goto eof;

			if (zb->capacity < min_bs) {
				td_verror(td, EINVAL, "ZCAP is less min_bs");
				log_err("zone capacity %"PRIu64" smaller than minimum block size %"PRIu64"\n",
					zb->capacity, min_bs);
				goto eof;
			}
		}

		/* Make writes occur at the write pointer */
		assert(!zbd_zone_full(f, zb, min_bs));
		io_u->offset = zb->wp;
		if (!is_valid_offset(f, io_u->offset)) {
			td_verror(td, EINVAL, "invalid WP value");
			dprint(FD_ZBD, "%s: dropped request with offset %llu\n",
			       f->file_name, io_u->offset);
			goto eof;
		}

		/*
		 * Make sure that the buflen is a multiple of the minimal
		 * block size. Give up if shrinking would make the request too
		 * small.
		 */
		new_len = min((unsigned long long)io_u->buflen,
			      zbd_zone_capacity_end(zb) - io_u->offset);
		new_len = new_len / min_bs * min_bs;
		if (new_len == io_u->buflen)
			goto accept;
		if (new_len >= min_bs) {
			io_u->buflen = new_len;
			dprint(FD_IO, "Changed length from %u into %llu\n",
			       orig_len, io_u->buflen);
			goto accept;
		}

		td_verror(td, EIO, "zone remainder too small");
		log_err("zone remainder %lld smaller than min block size %"PRIu64"\n",
			(zbd_zone_capacity_end(zb) - io_u->offset), min_bs);

		goto eof;

	case DDIR_TRIM:
		/* Check random trim targets a non-empty zone */
		if (!td_random(td) || zb->wp > zb->start)
			goto accept;

		/* Find out a non-empty zone to trim */
		zone_unlock(zb);
		zl = zbd_get_zone(f, f->max_zone);
		zb = zbd_find_zone(td, io_u, 1, zb, zl);
		if (zb) {
			io_u->offset = zb->start;
			dprint(FD_ZBD, "%s: found new zone(%lld) for trim\n",
			       f->file_name, io_u->offset);
			goto accept;
		}

		goto eof;

	case DDIR_SYNC:
		/* fall-through */
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
	case DDIR_WAIT:
	case DDIR_LAST:
	case DDIR_INVAL:
	case DDIR_TIMEOUT:
		goto accept;
	}

	assert(false);

accept:
	assert(zb->has_wp);
	assert(zb->cond != ZBD_ZONE_COND_OFFLINE);
	assert(!io_u->zbd_queue_io);
	assert(!io_u->zbd_put_io);

	io_u->zbd_queue_io = zbd_queue_io;
	io_u->zbd_put_io = zbd_put_io;
	if (io_u->ddir == DDIR_WRITE)
		zb->writes_in_flight++;

	/*
	 * Since we return with the zone lock still held,
	 * add an annotation to let Coverity know that it
	 * is intentional.
	 */
	/* coverity[missing_unlock] */

	return io_u_accept;

eof:
	if (zb && zb->has_wp)
		zone_unlock(zb);

	return io_u_eof;
}

/* Return a string with ZBD statistics */
char *zbd_write_status(const struct thread_stat *ts)
{
	char *res;

	if (asprintf(&res, "; %"PRIu64" zone resets", ts->nr_zone_resets) < 0)
		return NULL;
	return res;
}

/**
 * zbd_do_io_u_trim - If reset zone is applicable, do reset zone instead of trim
 *
 * @td: FIO thread data.
 * @io_u: FIO I/O unit.
 *
 * It is assumed that z->mutex is already locked.
 * Return io_u_completed when reset zone succeeds. Return 0 when the target zone
 * does not have write pointer. On error, return negative errno.
 */
int zbd_do_io_u_trim(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	int ret;

	z = zbd_offset_to_zone(f, io_u->offset);
	if (!z->has_wp)
		return 0;

	if (io_u->offset != z->start) {
		log_err("Trim offset not at zone start (%lld)\n",
			io_u->offset);
		return -EINVAL;
	}

	ret = zbd_reset_zone((struct thread_data *)td, f, z);
	if (ret < 0)
		return ret;

	return io_u_completed;
}

void zbd_log_err(const struct thread_data *td, const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;

	if (td->o.zone_mode != ZONE_MODE_ZBD)
		return;

	if (io_u->error == EOVERFLOW)
		log_err("%s: Exceeded max_active_zones limit. Check conditions of zones out of I/O ranges.\n",
			f->file_name);
}

void zbd_recover_write_error(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	struct zbd_zone zrep;
	unsigned long long retry_offset;
	unsigned long long retry_len;
	char *retry_buf;
	uint64_t write_end_offset;
	int ret;

	z = zbd_offset_to_zone(f, io_u->offset);
	if (!z->has_wp)
		return;
	write_end_offset = io_u->offset + io_u->buflen - z->start;

	assert(z->writes_in_flight);

	if (!z->fixing_zone_wp) {
		z->fixing_zone_wp = 1;
		dprint(FD_ZBD, "%s: Start fixing %u write pointer\n",
		       f->file_name, zbd_zone_idx(f, z));
	}

	if (z->max_write_error_offset < write_end_offset)
		z->max_write_error_offset = write_end_offset;

	if (z->writes_in_flight > 1)
		return;

	/*
	 * This is the last write to the zone since the write error to recover.
	 * Get the zone current write pointer and recover the write pointer
	 * position so that next write can continue.
	 */
	ret = zbd_report_zones(td, f, z->start, &zrep, 1);
	if (ret != 1) {
		log_info("fio: Report zone for write recovery failed for %s\n",
			 f->file_name);
		return;
	}

	if (zrep.wp < z->start ||
	    z->start + z->max_write_error_offset < zrep.wp ) {
		log_info("fio: unexpected write pointer position on error for %s: wp=%"PRIu64"\n",
			 f->file_name, zrep.wp);
		return;
	}

	retry_offset = zrep.wp;
	retry_len = z->start + z->max_write_error_offset - retry_offset;
	retry_buf = NULL;
	if (retry_offset >= io_u->offset)
		retry_buf = (char *)io_u->buf + (retry_offset - io_u->offset);

	ret = zbd_move_zone_wp(td, io_u->file, &zrep, retry_len, retry_buf);
	if (ret) {
		log_info("fio: Failed to recover write pointer for %s\n",
			 f->file_name);
		return;
	}

	z->wp = retry_offset + retry_len;

	dprint(FD_ZBD, "%s: Write pointer move succeeded for error=%d\n",
	       f->file_name, io_u->error);
}
