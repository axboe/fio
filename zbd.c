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

/**
 * zbd_get_zoned_model - Get a device zoned model
 * @td: FIO thread data
 * @f: FIO file for which to get model information
 */
int zbd_get_zoned_model(struct thread_data *td, struct fio_file *f,
			enum zbd_zoned_model *model)
{
	int ret;

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
int zbd_report_zones(struct thread_data *td, struct fio_file *f,
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
		log_err("%s: report zones from sector %llu failed (%d).\n",
			f->file_name, (unsigned long long)offset >> 9, errno);
	} else if (ret == 0) {
		td_verror(td, errno, "Empty zone report");
		log_err("%s: report zones from sector %llu is empty.\n",
			f->file_name, (unsigned long long)offset >> 9);
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
int zbd_reset_wp(struct thread_data *td, struct fio_file *f,
		 uint64_t offset, uint64_t length)
{
	int ret;

	if (td->io_ops && td->io_ops->reset_wp)
		ret = td->io_ops->reset_wp(td, f, offset, length);
	else
		ret = blkzoned_reset_wp(td, f, offset, length);
	if (ret < 0) {
		td_verror(td, errno, "resetting wp failed");
		log_err("%s: resetting wp for %llu sectors at sector %llu failed (%d).\n",
			f->file_name, (unsigned long long)length >> 9,
			(unsigned long long)offset >> 9, errno);
	}

	return ret;
}

/**
 * zbd_zone_idx - convert an offset into a zone number
 * @f: file pointer.
 * @offset: offset in bytes. If this offset is in the first zone_size bytes
 *	    past the disk size then the index of the sentinel is returned.
 */
static uint32_t zbd_zone_idx(const struct fio_file *f, uint64_t offset)
{
	uint32_t zone_idx;

	if (f->zbd_info->zone_size_log2 > 0)
		zone_idx = offset >> f->zbd_info->zone_size_log2;
	else
		zone_idx = offset / f->zbd_info->zone_size;

	return min(zone_idx, f->zbd_info->nr_zones);
}

/**
 * zbd_zone_swr - Test whether a zone requires sequential writes
 * @z: zone info pointer.
 */
static inline bool zbd_zone_swr(struct fio_zone_info *z)
{
	return z->type == ZBD_ZONE_TYPE_SWR;
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

	return zbd_zone_swr(z) &&
		z->wp + required > zbd_zone_capacity_end(z);
}

static void zone_lock(struct thread_data *td, struct fio_file *f, struct fio_zone_info *z)
{
	struct zoned_block_device_info *zbd = f->zbd_info;
	uint32_t nz = z - zbd->zone_info;

	/* A thread should never lock zones outside its working area. */
	assert(f->min_zone <= nz && nz < f->max_zone);

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

static bool is_valid_offset(const struct fio_file *f, uint64_t offset)
{
	return (uint64_t)(offset - f->file_offset) < f->io_size;
}

/* Verify whether direct I/O is used for all host-managed zoned drives. */
static bool zbd_using_direct_io(void)
{
	struct thread_data *td;
	struct fio_file *f;
	int i, j;

	for_each_td(td, i) {
		if (td->o.odirect || !(td->o.td_ddir & TD_DDIR_WRITE))
			continue;
		for_each_file(td, f, j) {
			if (f->zbd_info &&
			    f->zbd_info->model == ZBD_HOST_MANAGED)
				return false;
		}
	}

	return true;
}

/* Whether or not the I/O range for f includes one or more sequential zones */
static bool zbd_is_seq_job(struct fio_file *f)
{
	uint32_t zone_idx, zone_idx_b, zone_idx_e;

	assert(f->zbd_info);
	if (f->io_size == 0)
		return false;
	zone_idx_b = zbd_zone_idx(f, f->file_offset);
	zone_idx_e = zbd_zone_idx(f, f->file_offset + f->io_size - 1);
	for (zone_idx = zone_idx_b; zone_idx <= zone_idx_e; zone_idx++)
		if (zbd_zone_swr(&f->zbd_info->zone_info[zone_idx]))
			return true;

	return false;
}

/*
 * Verify whether offset and size parameters are aligned with zone boundaries.
 */
static bool zbd_verify_sizes(void)
{
	const struct fio_zone_info *z;
	struct thread_data *td;
	struct fio_file *f;
	uint64_t new_offset, new_end;
	uint32_t zone_idx;
	int i, j;

	for_each_td(td, i) {
		for_each_file(td, f, j) {
			if (!f->zbd_info)
				continue;
			if (f->file_offset >= f->real_file_size)
				continue;
			if (!zbd_is_seq_job(f))
				continue;

			if (!td->o.zone_size) {
				td->o.zone_size = f->zbd_info->zone_size;
				if (!td->o.zone_size) {
					log_err("%s: invalid 0 zone size\n",
						f->file_name);
					return false;
				}
			} else if (td->o.zone_size != f->zbd_info->zone_size) {
				log_err("%s: job parameter zonesize %llu does not match disk zone size %llu.\n",
					f->file_name, (unsigned long long) td->o.zone_size,
					(unsigned long long) f->zbd_info->zone_size);
				return false;
			}

			if (td->o.zone_skip &&
			    (td->o.zone_skip < td->o.zone_size ||
			     td->o.zone_skip % td->o.zone_size)) {
				log_err("%s: zoneskip %llu is not a multiple of the device zone size %llu.\n",
					f->file_name, (unsigned long long) td->o.zone_skip,
					(unsigned long long) td->o.zone_size);
				return false;
			}

			zone_idx = zbd_zone_idx(f, f->file_offset);
			z = &f->zbd_info->zone_info[zone_idx];
			if ((f->file_offset != z->start) &&
			    (td->o.td_ddir != TD_DDIR_READ)) {
				new_offset = zbd_zone_end(z);
				if (new_offset >= f->file_offset + f->io_size) {
					log_info("%s: io_size must be at least one zone\n",
						 f->file_name);
					return false;
				}
				log_info("%s: rounded up offset from %llu to %llu\n",
					 f->file_name, (unsigned long long) f->file_offset,
					 (unsigned long long) new_offset);
				f->io_size -= (new_offset - f->file_offset);
				f->file_offset = new_offset;
			}
			zone_idx = zbd_zone_idx(f, f->file_offset + f->io_size);
			z = &f->zbd_info->zone_info[zone_idx];
			new_end = z->start;
			if ((td->o.td_ddir != TD_DDIR_READ) &&
			    (f->file_offset + f->io_size != new_end)) {
				if (new_end <= f->file_offset) {
					log_info("%s: io_size must be at least one zone\n",
						 f->file_name);
					return false;
				}
				log_info("%s: rounded down io_size from %llu to %llu\n",
					 f->file_name, (unsigned long long) f->io_size,
					 (unsigned long long) new_end - f->file_offset);
				f->io_size = new_end - f->file_offset;
			}

			f->min_zone = zbd_zone_idx(f, f->file_offset);
			f->max_zone = zbd_zone_idx(f, f->file_offset + f->io_size);
			assert(f->min_zone < f->max_zone);
		}
	}

	return true;
}

static bool zbd_verify_bs(void)
{
	struct thread_data *td;
	struct fio_file *f;
	uint32_t zone_size;
	int i, j, k;

	for_each_td(td, i) {
		for_each_file(td, f, j) {
			if (!f->zbd_info)
				continue;
			zone_size = f->zbd_info->zone_size;
			for (k = 0; k < ARRAY_SIZE(td->o.bs); k++) {
				if (td->o.verify != VERIFY_NONE &&
				    zone_size % td->o.bs[k] != 0) {
					log_info("%s: block size %llu is not a divisor of the zone size %d\n",
						 f->file_name, td->o.bs[k],
						 zone_size);
					return false;
				}
			}
		}
	}
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
		log_err("%s: Specifying the zone size is mandatory for regular block devices with --zonemode=zbd\n\n",
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
			f->file_name, (unsigned long long) td->o.zone_capacity,
			(unsigned long long) td->o.zone_size);
		return 1;
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
	uint64_t zone_size, offset;
	struct zoned_block_device_info *zbd_info = NULL;
	int i, j, ret = 0;

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
	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;

	if (td->o.zone_size == 0) {
		td->o.zone_size = zone_size;
	} else if (td->o.zone_size != zone_size) {
		log_err("fio: %s job parameter zonesize %llu does not match disk zone size %llu.\n",
			f->file_name, (unsigned long long) td->o.zone_size,
			(unsigned long long) zone_size);
		ret = -EINVAL;
		goto out;
	}

	dprint(FD_ZBD, "Device %s has %d zones of size %llu KB\n", f->file_name,
	       nr_zones, (unsigned long long) zone_size / 1024);

	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	ret = -ENOMEM;
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
			p->type = z->type;
			p->cond = z->cond;
			if (j > 0 && p->start != p[-1].start + zone_size) {
				log_info("%s: invalid zone data\n",
					 f->file_name);
				ret = -EINVAL;
				goto out;
			}
		}
		z--;
		offset = z->start + z->len;
		if (j >= nr_zones)
			break;
		nrz = zbd_report_zones(td, f, offset,
					    zones, ZBD_REPORT_MAX_ZONES);
		if (nrz < 0) {
			ret = nrz;
			log_info("fio: report zones (offset %llu) failed for %s (%d).\n",
			 	 (unsigned long long)offset,
				 f->file_name, -ret);
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
	zbd_info = NULL;
	ret = 0;

out:
	sfree(zbd_info);
	free(zones);
	return ret;
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
	case ZBD_IGNORE:
		return 0;
	case ZBD_HOST_AWARE:
	case ZBD_HOST_MANAGED:
		ret = parse_zone_info(td, f);
		break;
	case ZBD_NONE:
		ret = init_zone_info(td, f);
		break;
	default:
		td_verror(td, EINVAL, "Unsupported zoned model");
		log_err("Unsupported zoned model\n");
		return -EINVAL;
	}

	if (ret == 0) {
		f->zbd_info->model = zbd_model;
		f->zbd_info->max_open_zones = td->o.max_open_zones;
	}
	return ret;
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
	struct thread_data *td2;
	struct fio_file *f2;
	int i, j, ret;

	for_each_td(td2, i) {
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
	}

	ret = zbd_create_zone_info(td, file);
	if (ret < 0)
		td_verror(td, -ret, "zbd_create_zone_info() failed");
	return ret;
}

static bool zbd_open_zone(struct thread_data *td, const struct fio_file *f,
			  uint32_t zone_idx);
static int zbd_reset_zone(struct thread_data *td, struct fio_file *f,
			  struct fio_zone_info *z);

int zbd_setup_files(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	for_each_file(td, f, i) {
		if (zbd_init_zone_info(td, f))
			return 1;
	}

	if (!zbd_using_direct_io()) {
		log_err("Using direct I/O is mandatory for writing to ZBD drives\n\n");
		return 1;
	}

	if (!zbd_verify_sizes())
		return 1;

	if (!zbd_verify_bs())
		return 1;

	for_each_file(td, f, i) {
		struct zoned_block_device_info *zbd = f->zbd_info;
		struct fio_zone_info *z;
		int zi;

		if (!zbd)
			continue;

		zbd->max_open_zones = zbd->max_open_zones ?: ZBD_MAX_OPEN_ZONES;

		if (td->o.max_open_zones > 0 &&
		    zbd->max_open_zones != td->o.max_open_zones) {
			log_err("Different 'max_open_zones' values\n");
			return 1;
		}
		if (zbd->max_open_zones > ZBD_MAX_OPEN_ZONES) {
			log_err("'max_open_zones' value is limited by %u\n", ZBD_MAX_OPEN_ZONES);
			return 1;
		}

		for (zi = f->min_zone; zi < f->max_zone; zi++) {
			z = &zbd->zone_info[zi];
			if (z->cond != ZBD_ZONE_COND_IMP_OPEN &&
			    z->cond != ZBD_ZONE_COND_EXP_OPEN)
				continue;
			if (zbd_open_zone(td, f, zi))
				continue;
			/*
			 * If the number of open zones exceeds specified limits,
			 * reset all extra open zones.
			 */
			if (zbd_reset_zone(td, f, z) < 0) {
				log_err("Failed to reest zone %d\n", zi);
				return 1;
			}
		}
	}

	return 0;
}

static unsigned int zbd_zone_nr(struct zoned_block_device_info *zbd_info,
				struct fio_zone_info *zone)
{
	return zone - zbd_info->zone_info;
}

/**
 * zbd_reset_zone - reset the write pointer of a single zone
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
	uint64_t offset = z->start;
	uint64_t length = (z+1)->start - offset;
	int ret = 0;

	if (z->wp == z->start)
		return 0;

	assert(is_valid_offset(f, offset + length - 1));

	dprint(FD_ZBD, "%s: resetting wp of zone %u.\n", f->file_name,
		zbd_zone_nr(f->zbd_info, z));
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

	pthread_mutex_lock(&f->zbd_info->mutex);
	f->zbd_info->sectors_with_data -= z->wp - z->start;
	pthread_mutex_unlock(&f->zbd_info->mutex);
	z->wp = z->start;
	z->verify_block = 0;

	td->ts.nr_zone_resets++;

	return ret;
}

/* The caller must hold f->zbd_info->mutex */
static void zbd_close_zone(struct thread_data *td, const struct fio_file *f,
			   unsigned int zone_idx)
{
	uint32_t open_zone_idx = 0;

	for (; open_zone_idx < f->zbd_info->num_open_zones; open_zone_idx++) {
		if (f->zbd_info->open_zones[open_zone_idx] == zone_idx)
			break;
	}
	if (open_zone_idx == f->zbd_info->num_open_zones) {
		dprint(FD_ZBD, "%s: zone %d is not open\n",
		       f->file_name, zone_idx);
		return;
	}

	dprint(FD_ZBD, "%s: closing zone %d\n", f->file_name, zone_idx);
	memmove(f->zbd_info->open_zones + open_zone_idx,
		f->zbd_info->open_zones + open_zone_idx + 1,
		(ZBD_MAX_OPEN_ZONES - (open_zone_idx + 1)) *
		sizeof(f->zbd_info->open_zones[0]));
	f->zbd_info->num_open_zones--;
	td->num_open_zones--;
	f->zbd_info->zone_info[zone_idx].open = 0;
}

/*
 * Reset a range of zones. Returns 0 upon success and 1 upon failure.
 * @td: fio thread data.
 * @f: fio file for which to reset zones
 * @zb: first zone to reset.
 * @ze: first zone not to reset.
 * @all_zones: whether to reset all zones or only those zones for which the
 *	write pointer is not a multiple of td->o.min_bs[DDIR_WRITE].
 */
static int zbd_reset_zones(struct thread_data *td, struct fio_file *f,
			   struct fio_zone_info *const zb,
			   struct fio_zone_info *const ze, bool all_zones)
{
	struct fio_zone_info *z;
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	bool reset_wp;
	int res = 0;

	assert(min_bs);

	dprint(FD_ZBD, "%s: examining zones %u .. %u\n", f->file_name,
		zbd_zone_nr(f->zbd_info, zb), zbd_zone_nr(f->zbd_info, ze));
	for (z = zb; z < ze; z++) {
		uint32_t nz = z - f->zbd_info->zone_info;

		if (!zbd_zone_swr(z))
			continue;
		zone_lock(td, f, z);
		if (all_zones) {
			pthread_mutex_lock(&f->zbd_info->mutex);
			zbd_close_zone(td, f, nz);
			pthread_mutex_unlock(&f->zbd_info->mutex);

			reset_wp = z->wp != z->start;
		} else {
			reset_wp = z->wp % min_bs != 0;
		}
		if (reset_wp) {
			dprint(FD_ZBD, "%s: resetting zone %u\n",
			       f->file_name,
			       zbd_zone_nr(f->zbd_info, z));
			if (zbd_reset_zone(td, f, z) < 0)
				res = 1;
		}
		pthread_mutex_unlock(&z->mutex);
	}

	return res;
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

enum swd_action {
	CHECK_SWD,
	SET_SWD,
};

/* Calculate the number of sectors with data (swd) and perform action 'a' */
static uint64_t zbd_process_swd(const struct fio_file *f, enum swd_action a)
{
	struct fio_zone_info *zb, *ze, *z;
	uint64_t swd = 0;

	zb = &f->zbd_info->zone_info[f->min_zone];
	ze = &f->zbd_info->zone_info[f->max_zone];
	for (z = zb; z < ze; z++) {
		pthread_mutex_lock(&z->mutex);
		swd += z->wp - z->start;
	}
	pthread_mutex_lock(&f->zbd_info->mutex);
	switch (a) {
	case CHECK_SWD:
		assert(f->zbd_info->sectors_with_data == swd);
		break;
	case SET_SWD:
		f->zbd_info->sectors_with_data = swd;
		break;
	}
	pthread_mutex_unlock(&f->zbd_info->mutex);
	for (z = zb; z < ze; z++)
		pthread_mutex_unlock(&z->mutex);

	return swd;
}

/*
 * The swd check is useful for debugging but takes too much time to leave
 * it enabled all the time. Hence it is disabled by default.
 */
static const bool enable_check_swd = false;

/* Check whether the value of zbd_info.sectors_with_data is correct. */
static void zbd_check_swd(const struct fio_file *f)
{
	if (!enable_check_swd)
		return;

	zbd_process_swd(f, CHECK_SWD);
}

static void zbd_init_swd(struct fio_file *f)
{
	uint64_t swd;

	if (!enable_check_swd)
		return;

	swd = zbd_process_swd(f, SET_SWD);
	dprint(FD_ZBD, "%s(%s): swd = %" PRIu64 "\n", __func__, f->file_name,
	       swd);
}

void zbd_file_reset(struct thread_data *td, struct fio_file *f)
{
	struct fio_zone_info *zb, *ze;

	if (!f->zbd_info || !td_write(td))
		return;

	zb = &f->zbd_info->zone_info[f->min_zone];
	ze = &f->zbd_info->zone_info[f->max_zone];
	zbd_init_swd(f);
	/*
	 * If data verification is enabled reset the affected zones before
	 * writing any data to avoid that a zone reset has to be issued while
	 * writing data, which causes data loss.
	 */
	zbd_reset_zones(td, f, zb, ze, td->o.verify != VERIFY_NONE &&
			td->runstate != TD_VERIFYING);
	zbd_reset_write_cnt(td, f);
}

/* The caller must hold f->zbd_info->mutex. */
static bool is_zone_open(const struct thread_data *td, const struct fio_file *f,
			 unsigned int zone_idx)
{
	struct zoned_block_device_info *zbdi = f->zbd_info;
	int i;

	assert(td->o.job_max_open_zones == 0 || td->num_open_zones <= td->o.job_max_open_zones);
	assert(td->o.job_max_open_zones <= zbdi->max_open_zones);
	assert(zbdi->num_open_zones <= zbdi->max_open_zones);

	for (i = 0; i < zbdi->num_open_zones; i++)
		if (zbdi->open_zones[i] == zone_idx)
			return true;

	return false;
}

/*
 * Open a ZBD zone if it was not yet open. Returns true if either the zone was
 * already open or if opening a new zone is allowed. Returns false if the zone
 * was not yet open and opening a new zone would cause the zone limit to be
 * exceeded.
 */
static bool zbd_open_zone(struct thread_data *td, const struct fio_file *f,
			  uint32_t zone_idx)
{
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	struct fio_zone_info *z = &f->zbd_info->zone_info[zone_idx];
	bool res = true;

	if (z->cond == ZBD_ZONE_COND_OFFLINE)
		return false;

	/*
	 * Skip full zones with data verification enabled because resetting a
	 * zone causes data loss and hence causes verification to fail.
	 */
	if (td->o.verify != VERIFY_NONE && zbd_zone_full(f, z, min_bs))
		return false;

	pthread_mutex_lock(&f->zbd_info->mutex);
	if (is_zone_open(td, f, zone_idx)) {
		/*
		 * If the zone is already open and going to be full by writes
		 * in-flight, handle it as a full zone instead of an open zone.
		 */
		if (z->wp >= zbd_zone_capacity_end(z))
			res = false;
		goto out;
	}
	res = false;
	/* Zero means no limit */
	if (td->o.job_max_open_zones > 0 &&
	    td->num_open_zones >= td->o.job_max_open_zones)
		goto out;
	if (f->zbd_info->num_open_zones >= f->zbd_info->max_open_zones)
		goto out;
	dprint(FD_ZBD, "%s: opening zone %d\n", f->file_name, zone_idx);
	f->zbd_info->open_zones[f->zbd_info->num_open_zones++] = zone_idx;
	td->num_open_zones++;
	z->open = 1;
	res = true;

out:
	pthread_mutex_unlock(&f->zbd_info->mutex);
	return res;
}

/* Anything goes as long as it is not a constant. */
static uint32_t pick_random_zone_idx(const struct fio_file *f,
				     const struct io_u *io_u)
{
	return io_u->offset * f->zbd_info->num_open_zones / f->real_file_size;
}

/*
 * Modify the offset of an I/O unit that does not refer to an open zone such
 * that it refers to an open zone. Close an open zone and open a new zone if
 * necessary. This algorithm can only work correctly if all write pointers are
 * a multiple of the fio block size. The caller must neither hold z->mutex
 * nor f->zbd_info->mutex. Returns with z->mutex held upon success.
 */
static struct fio_zone_info *zbd_convert_to_open_zone(struct thread_data *td,
						      struct io_u *io_u)
{
	const uint32_t min_bs = td->o.min_bs[io_u->ddir];
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	unsigned int open_zone_idx = -1;
	uint32_t zone_idx, new_zone_idx;
	int i;
	bool wait_zone_close;

	assert(is_valid_offset(f, io_u->offset));

	if (td->o.max_open_zones || td->o.job_max_open_zones) {
		/*
		 * This statement accesses f->zbd_info->open_zones[] on purpose
		 * without locking.
		 */
		zone_idx = f->zbd_info->open_zones[pick_random_zone_idx(f, io_u)];
	} else {
		zone_idx = zbd_zone_idx(f, io_u->offset);
	}
	if (zone_idx < f->min_zone)
		zone_idx = f->min_zone;
	else if (zone_idx >= f->max_zone)
		zone_idx = f->max_zone - 1;
	dprint(FD_ZBD, "%s(%s): starting from zone %d (offset %lld, buflen %lld)\n",
	       __func__, f->file_name, zone_idx, io_u->offset, io_u->buflen);

	/*
	 * Since z->mutex is the outer lock and f->zbd_info->mutex the inner
	 * lock it can happen that the state of the zone with index zone_idx
	 * has changed after 'z' has been assigned and before f->zbd_info->mutex
	 * has been obtained. Hence the loop.
	 */
	for (;;) {
		uint32_t tmp_idx;

		z = &f->zbd_info->zone_info[zone_idx];

		zone_lock(td, f, z);
		pthread_mutex_lock(&f->zbd_info->mutex);
		if (td->o.max_open_zones == 0 && td->o.job_max_open_zones == 0)
			goto examine_zone;
		if (f->zbd_info->num_open_zones == 0) {
			dprint(FD_ZBD, "%s(%s): no zones are open\n",
			       __func__, f->file_name);
			goto open_other_zone;
		}

		/*
		 * List of opened zones is per-device, shared across all threads.
		 * Start with quasi-random candidate zone.
		 * Ignore zones which don't belong to thread's offset/size area.
		 */
		open_zone_idx = pick_random_zone_idx(f, io_u);
		assert(open_zone_idx < f->zbd_info->num_open_zones);
		tmp_idx = open_zone_idx;
		for (i = 0; i < f->zbd_info->num_open_zones; i++) {
			uint32_t tmpz;

			if (tmp_idx >= f->zbd_info->num_open_zones)
				tmp_idx = 0;
			tmpz = f->zbd_info->open_zones[tmp_idx];
			if (f->min_zone <= tmpz && tmpz < f->max_zone) {
				open_zone_idx = tmp_idx;
				goto found_candidate_zone;
			}

			tmp_idx++;
		}

		dprint(FD_ZBD, "%s(%s): no candidate zone\n",
			__func__, f->file_name);
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
		return NULL;

found_candidate_zone:
		new_zone_idx = f->zbd_info->open_zones[open_zone_idx];
		if (new_zone_idx == zone_idx)
			break;
		zone_idx = new_zone_idx;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
	}

	/* Both z->mutex and f->zbd_info->mutex are held. */

examine_zone:
	if (z->wp + min_bs <= zbd_zone_capacity_end(z)) {
		pthread_mutex_unlock(&f->zbd_info->mutex);
		goto out;
	}

open_other_zone:
	/* Check if number of open zones reaches one of limits. */
	wait_zone_close =
		f->zbd_info->num_open_zones == f->max_zone - f->min_zone ||
		(td->o.max_open_zones &&
		 f->zbd_info->num_open_zones == td->o.max_open_zones) ||
		(td->o.job_max_open_zones &&
		 td->num_open_zones == td->o.job_max_open_zones);

	pthread_mutex_unlock(&f->zbd_info->mutex);

	/* Only z->mutex is held. */

	/*
	 * When number of open zones reaches to one of limits, wait for
	 * zone close before opening a new zone.
	 */
	if (wait_zone_close) {
		dprint(FD_ZBD, "%s(%s): quiesce to allow open zones to close\n",
		       __func__, f->file_name);
		io_u_quiesce(td);
	}

	/* Zone 'z' is full, so try to open a new zone. */
	for (i = f->io_size / f->zbd_info->zone_size; i > 0; i--) {
		zone_idx++;
		pthread_mutex_unlock(&z->mutex);
		z++;
		if (!is_valid_offset(f, z->start)) {
			/* Wrap-around. */
			zone_idx = f->min_zone;
			z = &f->zbd_info->zone_info[zone_idx];
		}
		assert(is_valid_offset(f, z->start));
		zone_lock(td, f, z);
		if (z->open)
			continue;
		if (zbd_open_zone(td, f, zone_idx))
			goto out;
	}

	/* Only z->mutex is held. */

	/* Check whether the write fits in any of the already opened zones. */
	pthread_mutex_lock(&f->zbd_info->mutex);
	for (i = 0; i < f->zbd_info->num_open_zones; i++) {
		zone_idx = f->zbd_info->open_zones[i];
		if (zone_idx < f->min_zone || zone_idx >= f->max_zone)
			continue;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);

		z = &f->zbd_info->zone_info[zone_idx];

		zone_lock(td, f, z);
		if (z->wp + min_bs <= zbd_zone_capacity_end(z))
			goto out;
		pthread_mutex_lock(&f->zbd_info->mutex);
	}
	pthread_mutex_unlock(&f->zbd_info->mutex);
	pthread_mutex_unlock(&z->mutex);
	dprint(FD_ZBD, "%s(%s): did not open another zone\n", __func__,
	       f->file_name);
	return NULL;

out:
	dprint(FD_ZBD, "%s(%s): returning zone %d\n", __func__, f->file_name,
	       zone_idx);
	io_u->offset = z->start;
	return z;
}

/* The caller must hold z->mutex. */
static struct fio_zone_info *zbd_replay_write_order(struct thread_data *td,
						    struct io_u *io_u,
						    struct fio_zone_info *z)
{
	const struct fio_file *f = io_u->file;
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];

	if (!zbd_open_zone(td, f, z - f->zbd_info->zone_info)) {
		pthread_mutex_unlock(&z->mutex);
		z = zbd_convert_to_open_zone(td, io_u);
		assert(z);
	}

	if (z->verify_block * min_bs >= z->capacity)
		log_err("%s: %d * %d >= %llu\n", f->file_name, z->verify_block,
			min_bs, (unsigned long long)z->capacity);
	io_u->offset = z->start + z->verify_block++ * min_bs;
	return z;
}

/*
 * Find another zone for which @io_u fits below the write pointer. Start
 * searching in zones @zb + 1 .. @zl and continue searching in zones
 * @zf .. @zb - 1.
 *
 * Either returns NULL or returns a zone pointer and holds the mutex for that
 * zone.
 */
static struct fio_zone_info *
zbd_find_zone(struct thread_data *td, struct io_u *io_u,
	      struct fio_zone_info *zb, struct fio_zone_info *zl)
{
	const uint32_t min_bs = td->o.min_bs[io_u->ddir];
	struct fio_file *f = io_u->file;
	struct fio_zone_info *z1, *z2;
	const struct fio_zone_info *const zf =
		&f->zbd_info->zone_info[f->min_zone];

	/*
	 * Skip to the next non-empty zone in case of sequential I/O and to
	 * the nearest non-empty zone in case of random I/O.
	 */
	for (z1 = zb + 1, z2 = zb - 1; z1 < zl || z2 >= zf; z1++, z2--) {
		if (z1 < zl && z1->cond != ZBD_ZONE_COND_OFFLINE) {
			zone_lock(td, f, z1);
			if (z1->start + min_bs <= z1->wp)
				return z1;
			pthread_mutex_unlock(&z1->mutex);
		} else if (!td_random(td)) {
			break;
		}
		if (td_random(td) && z2 >= zf &&
		    z2->cond != ZBD_ZONE_COND_OFFLINE) {
			zone_lock(td, f, z2);
			if (z2->start + min_bs <= z2->wp)
				return z2;
			pthread_mutex_unlock(&z2->mutex);
		}
	}
	dprint(FD_ZBD, "%s: adjusting random read offset failed\n",
	       f->file_name);
	return NULL;
}

/**
 * zbd_end_zone_io - update zone status at command completion
 * @io_u: I/O unit
 * @z: zone info pointer
 *
 * If the write command made the zone full, close it.
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
		zbd_close_zone(td, f, z - f->zbd_info->zone_info);
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
static void zbd_queue_io(struct thread_data *td, struct io_u *io_u, int q,
			 bool success)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx;
	uint64_t zone_end;

	if (!zbd_info)
		return;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	assert(zone_idx < zbd_info->nr_zones);
	z = &zbd_info->zone_info[zone_idx];

	if (!zbd_zone_swr(z))
		return;

	if (!success)
		goto unlock;

	dprint(FD_ZBD,
	       "%s: queued I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zone_idx);

	switch (io_u->ddir) {
	case DDIR_WRITE:
		zone_end = min((uint64_t)(io_u->offset + io_u->buflen),
			       zbd_zone_capacity_end(z));
		pthread_mutex_lock(&zbd_info->mutex);
		/*
		 * z->wp > zone_end means that one or more I/O errors
		 * have occurred.
		 */
		if (z->wp <= zone_end)
			zbd_info->sectors_with_data += zone_end - z->wp;
		pthread_mutex_unlock(&zbd_info->mutex);
		z->wp = zone_end;
		break;
	case DDIR_TRIM:
		assert(z->wp == z->start);
		break;
	default:
		break;
	}

	if (q == FIO_Q_COMPLETED && !io_u->error)
		zbd_end_zone_io(td, io_u, z);

unlock:
	if (!success || q != FIO_Q_QUEUED) {
		/* BUSY or COMPLETED: unlock the zone */
		pthread_mutex_unlock(&z->mutex);
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
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx;
	int ret;

	if (!zbd_info)
		return;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	assert(zone_idx < zbd_info->nr_zones);
	z = &zbd_info->zone_info[zone_idx];

	if (!zbd_zone_swr(z))
		return;

	dprint(FD_ZBD,
	       "%s: terminate I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zone_idx);

	zbd_end_zone_io(td, io_u, z);

	ret = pthread_mutex_unlock(&z->mutex);
	assert(ret == 0);
	zbd_check_swd(f);
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
	uint32_t zone_idx;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);
	assert(td->o.zone_size);

	zone_idx = zbd_zone_idx(f, f->last_pos[ddir]);
	z = &f->zbd_info->zone_info[zone_idx];

	/*
	 * When the zone capacity is smaller than the zone size and the I/O is
	 * sequential write, skip to zone end if the latest position is at the
	 * zone capacity limit.
	 */
	if (z->capacity < f->zbd_info->zone_size && !td_random(td) &&
	    ddir == DDIR_WRITE &&
	    f->last_pos[ddir] >= zbd_zone_capacity_end(z)) {
		dprint(FD_ZBD,
		       "%s: Jump from zone capacity limit to zone end:"
		       " (%llu -> %llu) for zone %u (%llu)\n",
		       f->file_name, (unsigned long long) f->last_pos[ddir],
		       (unsigned long long) zbd_zone_end(z),
		       zbd_zone_nr(f->zbd_info, z),
		       (unsigned long long) z->capacity);
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
	if (ddir != DDIR_READ || !td_rw(td))
		return ddir;

	if (io_u->file->zbd_info->sectors_with_data ||
	    td->o.read_beyond_wp)
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
	uint32_t zone_idx_b;
	struct fio_zone_info *zb, *zl, *orig_zb;
	uint32_t orig_len = io_u->buflen;
	uint32_t min_bs = td->o.min_bs[io_u->ddir];
	uint64_t new_len;
	int64_t range;

	if (!f->zbd_info)
		return io_u_accept;

	assert(min_bs);
	assert(is_valid_offset(f, io_u->offset));
	assert(io_u->buflen);
	zone_idx_b = zbd_zone_idx(f, io_u->offset);
	zb = &f->zbd_info->zone_info[zone_idx_b];
	orig_zb = zb;

	/* Accept the I/O offset for conventional zones. */
	if (!zbd_zone_swr(zb))
		return io_u_accept;

	/*
	 * Accept the I/O offset for reads if reading beyond the write pointer
	 * is enabled.
	 */
	if (zb->cond != ZBD_ZONE_COND_OFFLINE &&
	    io_u->ddir == DDIR_READ && td->o.read_beyond_wp)
		return io_u_accept;

	zbd_check_swd(f);

	zone_lock(td, f, zb);

	switch (io_u->ddir) {
	case DDIR_READ:
		if (td->runstate == TD_VERIFYING && td_write(td)) {
			zb = zbd_replay_write_order(td, io_u, zb);
			pthread_mutex_unlock(&zb->mutex);
			goto accept;
		}
		/*
		 * Check that there is enough written data in the zone to do an
		 * I/O of at least min_bs B. If there isn't, find a new zone for
		 * the I/O.
		 */
		range = zb->cond != ZBD_ZONE_COND_OFFLINE ?
			zb->wp - zb->start : 0;
		if (range < min_bs ||
		    ((!td_random(td)) && (io_u->offset + min_bs > zb->wp))) {
			pthread_mutex_unlock(&zb->mutex);
			zl = &f->zbd_info->zone_info[f->max_zone];
			zb = zbd_find_zone(td, io_u, zb, zl);
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
		if (io_u->buflen > f->zbd_info->zone_size)
			goto eof;
		if (!zbd_open_zone(td, f, zone_idx_b)) {
			pthread_mutex_unlock(&zb->mutex);
			zb = zbd_convert_to_open_zone(td, io_u);
			if (!zb)
				goto eof;
			zone_idx_b = zb - f->zbd_info->zone_info;
		}
		/* Check whether the zone reset threshold has been exceeded */
		if (td->o.zrf.u.f) {
			if (f->zbd_info->sectors_with_data >=
			    f->io_size * td->o.zrt.u.f &&
			    zbd_dec_and_reset_write_cnt(td, f)) {
				zb->reset_zone = 1;
			}
		}
		/* Reset the zone pointer if necessary */
		if (zb->reset_zone || zbd_zone_full(f, zb, min_bs)) {
			assert(td->o.verify == VERIFY_NONE);
			/*
			 * Since previous write requests may have been submitted
			 * asynchronously and since we will submit the zone
			 * reset synchronously, wait until previously submitted
			 * write requests have completed before issuing a
			 * zone reset.
			 */
			io_u_quiesce(td);
			zb->reset_zone = 0;
			if (zbd_reset_zone(td, f, zb) < 0)
				goto eof;

			if (zb->capacity < min_bs) {
				log_err("zone capacity %llu smaller than minimum block size %d\n",
					(unsigned long long)zb->capacity,
					min_bs);
				goto eof;
			}
		}
		/* Make writes occur at the write pointer */
		assert(!zbd_zone_full(f, zb, min_bs));
		io_u->offset = zb->wp;
		if (!is_valid_offset(f, io_u->offset)) {
			dprint(FD_ZBD, "Dropped request with offset %llu\n",
			       io_u->offset);
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
		log_err("Zone remainder %lld smaller than minimum block size %d\n",
			(zbd_zone_capacity_end(zb) - io_u->offset),
			min_bs);
		goto eof;
	case DDIR_TRIM:
		/* fall-through */
	case DDIR_SYNC:
	case DDIR_DATASYNC:
	case DDIR_SYNC_FILE_RANGE:
	case DDIR_WAIT:
	case DDIR_LAST:
	case DDIR_INVAL:
		goto accept;
	}

	assert(false);

accept:
	assert(zb);
	assert(zb->cond != ZBD_ZONE_COND_OFFLINE);
	assert(!io_u->zbd_queue_io);
	assert(!io_u->zbd_put_io);
	io_u->zbd_queue_io = zbd_queue_io;
	io_u->zbd_put_io = zbd_put_io;
	return io_u_accept;

eof:
	if (zb)
		pthread_mutex_unlock(&zb->mutex);
	return io_u_eof;
}

/* Return a string with ZBD statistics */
char *zbd_write_status(const struct thread_stat *ts)
{
	char *res;

	if (asprintf(&res, "; %llu zone resets", (unsigned long long) ts->nr_zone_resets) < 0)
		return NULL;
	return res;
}
