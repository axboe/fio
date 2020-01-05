/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/blkzoned.h>

#include "file.h"
#include "fio.h"
#include "lib/pow2.h"
#include "log.h"
#include "oslib/asprintf.h"
#include "smalloc.h"
#include "verify.h"
#include "zbd.h"

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

	return z->type == BLK_ZONE_TYPE_SEQWRITE_REQ &&
		z->wp + required > z->start + f->zbd_info->zone_size;
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
			    f->zbd_info->model == ZBD_DM_HOST_MANAGED)
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
		if (f->zbd_info->zone_info[zone_idx].type ==
		    BLK_ZONE_TYPE_SEQWRITE_REQ)
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
			if (f->file_offset != z->start) {
				new_offset = (z+1)->start;
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
			if (f->file_offset + f->io_size != new_end) {
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

/*
 * Read zone information into @buf starting from sector @start_sector.
 * @fd is a file descriptor that refers to a block device and @bufsz is the
 * size of @buf.
 *
 * Returns 0 upon success and a negative error code upon failure.
 * If the zone report is empty, always assume an error (device problem) and
 * return -EIO.
 */
static int read_zone_info(int fd, uint64_t start_sector,
			  void *buf, unsigned int bufsz)
{
	struct blk_zone_report *hdr = buf;
	int ret;

	if (bufsz < sizeof(*hdr))
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));

	hdr->nr_zones = (bufsz - sizeof(*hdr)) / sizeof(struct blk_zone);
	hdr->sector = start_sector;
	ret = ioctl(fd, BLKREPORTZONE, hdr);
	if (ret)
		return -errno;
	if (!hdr->nr_zones)
		return -EIO;
	return 0;
}

/*
 * Read up to 255 characters from the first line of a file. Strip the trailing
 * newline.
 */
static char *read_file(const char *path)
{
	char line[256], *p = line;
	FILE *f;

	f = fopen(path, "rb");
	if (!f)
		return NULL;
	if (!fgets(line, sizeof(line), f))
		line[0] = '\0';
	strsep(&p, "\n");
	fclose(f);

	return strdup(line);
}

static enum blk_zoned_model get_zbd_model(const char *file_name)
{
	enum blk_zoned_model model = ZBD_DM_NONE;
	char *zoned_attr_path = NULL;
	char *model_str = NULL;
	struct stat statbuf;
	char *sys_devno_path = NULL;
	char *part_attr_path = NULL;
	char *part_str = NULL;
	char sys_path[PATH_MAX];
	ssize_t sz;
	char *delim = NULL;

	if (stat(file_name, &statbuf) < 0)
		goto out;

	if (asprintf(&sys_devno_path, "/sys/dev/block/%d:%d",
		     major(statbuf.st_rdev), minor(statbuf.st_rdev)) < 0)
		goto out;

	sz = readlink(sys_devno_path, sys_path, sizeof(sys_path) - 1);
	if (sz < 0)
		goto out;
	sys_path[sz] = '\0';

	/*
	 * If the device is a partition device, cut the device name in the
	 * canonical sysfs path to obtain the sysfs path of the holder device.
	 *   e.g.:  /sys/devices/.../sda/sda1 -> /sys/devices/.../sda
	 */
	if (asprintf(&part_attr_path, "/sys/dev/block/%s/partition",
		     sys_path) < 0)
		goto out;
	part_str = read_file(part_attr_path);
	if (part_str && *part_str == '1') {
		delim = strrchr(sys_path, '/');
		if (!delim)
			goto out;
		*delim = '\0';
	}

	if (asprintf(&zoned_attr_path,
		     "/sys/dev/block/%s/queue/zoned", sys_path) < 0)
		goto out;

	model_str = read_file(zoned_attr_path);
	if (!model_str)
		goto out;
	dprint(FD_ZBD, "%s: zbd model string: %s\n", file_name, model_str);
	if (strcmp(model_str, "host-aware") == 0)
		model = ZBD_DM_HOST_AWARE;
	else if (strcmp(model_str, "host-managed") == 0)
		model = ZBD_DM_HOST_MANAGED;

out:
	free(model_str);
	free(zoned_attr_path);
	free(part_str);
	free(part_attr_path);
	free(sys_devno_path);
	return model;
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
	struct zoned_block_device_info *zbd_info = NULL;
	pthread_mutexattr_t attr;
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

	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;
	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	if (!zbd_info)
		return -ENOMEM;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutexattr_setpshared(&attr, true);
	pthread_mutex_init(&zbd_info->mutex, &attr);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (i = 0; i < nr_zones; i++, p++) {
		pthread_mutex_init(&p->mutex, &attr);
		p->start = i * zone_size;
		p->wp = p->start + zone_size;
		p->type = BLK_ZONE_TYPE_SEQWRITE_REQ;
		p->cond = BLK_ZONE_COND_EMPTY;
	}
	/* a sentinel */
	p->start = nr_zones * zone_size;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : -1;
	f->zbd_info->nr_zones = nr_zones;
	pthread_mutexattr_destroy(&attr);
	return 0;
}

/*
 * Parse the BLKREPORTZONE output and store it in f->zbd_info. Must be called
 * only for devices that support this ioctl, namely zoned block devices.
 */
static int parse_zone_info(struct thread_data *td, struct fio_file *f)
{
	const unsigned int bufsz = sizeof(struct blk_zone_report) +
		4096 * sizeof(struct blk_zone);
	uint32_t nr_zones;
	struct blk_zone_report *hdr;
	const struct blk_zone *z;
	struct fio_zone_info *p;
	uint64_t zone_size, start_sector;
	struct zoned_block_device_info *zbd_info = NULL;
	pthread_mutexattr_t attr;
	void *buf;
	int fd, i, j, ret = 0;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutexattr_setpshared(&attr, true);

	buf = malloc(bufsz);
	if (!buf)
		goto out;

	fd = open(f->file_name, O_RDONLY | O_LARGEFILE);
	if (fd < 0) {
		ret = -errno;
		goto free;
	}

	ret = read_zone_info(fd, 0, buf, bufsz);
	if (ret < 0) {
		log_info("fio: BLKREPORTZONE(%lu) failed for %s (%d).\n",
			 0UL, f->file_name, -ret);
		goto close;
	}
	hdr = buf;
	if (hdr->nr_zones < 1) {
		log_info("fio: %s has invalid zone information.\n",
			 f->file_name);
		goto close;
	}
	z = (void *)(hdr + 1);
	zone_size = z->len << 9;
	nr_zones = (f->real_file_size + zone_size - 1) / zone_size;

	if (td->o.zone_size == 0) {
		td->o.zone_size = zone_size;
	} else if (td->o.zone_size != zone_size) {
		log_err("fio: %s job parameter zonesize %llu does not match disk zone size %llu.\n",
			f->file_name, (unsigned long long) td->o.zone_size,
			(unsigned long long) zone_size);
		ret = -EINVAL;
		goto close;
	}

	dprint(FD_ZBD, "Device %s has %d zones of size %llu KB\n", f->file_name,
	       nr_zones, (unsigned long long) zone_size / 1024);

	zbd_info = scalloc(1, sizeof(*zbd_info) +
			   (nr_zones + 1) * sizeof(zbd_info->zone_info[0]));
	ret = -ENOMEM;
	if (!zbd_info)
		goto close;
	pthread_mutex_init(&zbd_info->mutex, &attr);
	zbd_info->refcount = 1;
	p = &zbd_info->zone_info[0];
	for (start_sector = 0, j = 0; j < nr_zones;) {
		z = (void *)(hdr + 1);
		for (i = 0; i < hdr->nr_zones; i++, j++, z++, p++) {
			pthread_mutex_init(&p->mutex, &attr);
			p->start = z->start << 9;
			switch (z->cond) {
			case BLK_ZONE_COND_NOT_WP:
			case BLK_ZONE_COND_FULL:
				p->wp = p->start + zone_size;
				break;
			default:
				assert(z->start <= z->wp);
				assert(z->wp <= z->start + (zone_size >> 9));
				p->wp = z->wp << 9;
				break;
			}
			p->type = z->type;
			p->cond = z->cond;
			if (j > 0 && p->start != p[-1].start + zone_size) {
				log_info("%s: invalid zone data\n",
					 f->file_name);
				ret = -EINVAL;
				goto close;
			}
		}
		z--;
		start_sector = z->start + z->len;
		if (j >= nr_zones)
			break;
		ret = read_zone_info(fd, start_sector, buf, bufsz);
		if (ret < 0) {
			log_info("fio: BLKREPORTZONE(%llu) failed for %s (%d).\n",
				 (unsigned long long) start_sector, f->file_name, -ret);
			goto close;
		}
	}
	/* a sentinel */
	zbd_info->zone_info[nr_zones].start = start_sector << 9;

	f->zbd_info = zbd_info;
	f->zbd_info->zone_size = zone_size;
	f->zbd_info->zone_size_log2 = is_power_of_2(zone_size) ?
		ilog2(zone_size) : -1;
	f->zbd_info->nr_zones = nr_zones;
	zbd_info = NULL;
	ret = 0;

close:
	sfree(zbd_info);
	close(fd);
free:
	free(buf);
out:
	pthread_mutexattr_destroy(&attr);
	return ret;
}

/*
 * Allocate zone information and store it into f->zbd_info if zonemode=zbd.
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_create_zone_info(struct thread_data *td, struct fio_file *f)
{
	enum blk_zoned_model zbd_model;
	int ret = 0;

	assert(td->o.zone_mode == ZONE_MODE_ZBD);

	zbd_model = get_zbd_model(f->file_name);
	switch (zbd_model) {
	case ZBD_DM_HOST_AWARE:
	case ZBD_DM_HOST_MANAGED:
		ret = parse_zone_info(td, f);
		break;
	case ZBD_DM_NONE:
		ret = init_zone_info(td, f);
		break;
	}
	if (ret == 0)
		f->zbd_info->model = zbd_model;
	return ret;
}

void zbd_free_zone_info(struct fio_file *f)
{
	uint32_t refcount;

	if (!f->zbd_info)
		return;

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

int zbd_init(struct thread_data *td)
{
	struct fio_file *f;
	int i;

	for_each_file(td, f, i) {
		if (f->filetype != FIO_TYPE_BLOCK)
			continue;
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

	return 0;
}

/**
 * zbd_reset_range - reset zones for a range of sectors
 * @td: FIO thread data.
 * @f: Fio file for which to reset zones
 * @sector: Starting sector in units of 512 bytes
 * @nr_sectors: Number of sectors in units of 512 bytes
 *
 * Returns 0 upon success and a negative error code upon failure.
 */
static int zbd_reset_range(struct thread_data *td, const struct fio_file *f,
			   uint64_t offset, uint64_t length)
{
	struct blk_zone_range zr = {
		.sector         = offset >> 9,
		.nr_sectors     = length >> 9,
	};
	uint32_t zone_idx_b, zone_idx_e;
	struct fio_zone_info *zb, *ze, *z;
	int ret = 0;

	assert(f->fd != -1);
	assert(is_valid_offset(f, offset + length - 1));
	switch (f->zbd_info->model) {
	case ZBD_DM_HOST_AWARE:
	case ZBD_DM_HOST_MANAGED:
		ret = ioctl(f->fd, BLKRESETZONE, &zr);
		if (ret < 0) {
			td_verror(td, errno, "resetting wp failed");
			log_err("%s: resetting wp for %llu sectors at sector %llu failed (%d).\n",
				f->file_name, zr.nr_sectors, zr.sector, errno);
			return ret;
		}
		break;
	case ZBD_DM_NONE:
		break;
	}

	zone_idx_b = zbd_zone_idx(f, offset);
	zb = &f->zbd_info->zone_info[zone_idx_b];
	zone_idx_e = zbd_zone_idx(f, offset + length);
	ze = &f->zbd_info->zone_info[zone_idx_e];
	for (z = zb; z < ze; z++) {
		pthread_mutex_lock(&z->mutex);
		pthread_mutex_lock(&f->zbd_info->mutex);
		f->zbd_info->sectors_with_data -= z->wp - z->start;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		z->wp = z->start;
		z->verify_block = 0;
		pthread_mutex_unlock(&z->mutex);
	}

	td->ts.nr_zone_resets += ze - zb;

	return ret;
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
 */
static int zbd_reset_zone(struct thread_data *td, const struct fio_file *f,
			  struct fio_zone_info *z)
{
	dprint(FD_ZBD, "%s: resetting wp of zone %u.\n", f->file_name,
		zbd_zone_nr(f->zbd_info, z));

	return zbd_reset_range(td, f, z->start, (z+1)->start - z->start);
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
	struct fio_zone_info *z, *start_z = ze;
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	bool reset_wp;
	int res = 0;

	dprint(FD_ZBD, "%s: examining zones %u .. %u\n", f->file_name,
		zbd_zone_nr(f->zbd_info, zb), zbd_zone_nr(f->zbd_info, ze));
	assert(f->fd != -1);
	for (z = zb; z < ze; z++) {
		pthread_mutex_lock(&z->mutex);
		switch (z->type) {
		case BLK_ZONE_TYPE_SEQWRITE_REQ:
			reset_wp = all_zones ? z->wp != z->start :
					(td->o.td_ddir & TD_DDIR_WRITE) &&
					z->wp % min_bs != 0;
			if (start_z == ze && reset_wp) {
				start_z = z;
			} else if (start_z < ze && !reset_wp) {
				dprint(FD_ZBD,
				       "%s: resetting zones %u .. %u\n",
				       f->file_name,
					zbd_zone_nr(f->zbd_info, start_z),
					zbd_zone_nr(f->zbd_info, z));
				if (zbd_reset_range(td, f, start_z->start,
						z->start - start_z->start) < 0)
					res = 1;
				start_z = ze;
			}
			break;
		default:
			if (start_z == ze)
				break;
			dprint(FD_ZBD, "%s: resetting zones %u .. %u\n",
			       f->file_name, zbd_zone_nr(f->zbd_info, start_z),
			       zbd_zone_nr(f->zbd_info, z));
			if (zbd_reset_range(td, f, start_z->start,
					    z->start - start_z->start) < 0)
				res = 1;
			start_z = ze;
			break;
		}
	}
	if (start_z < ze) {
		dprint(FD_ZBD, "%s: resetting zones %u .. %u\n", f->file_name,
			zbd_zone_nr(f->zbd_info, start_z),
			zbd_zone_nr(f->zbd_info, z));
		if (zbd_reset_range(td, f, start_z->start,
				    z->start - start_z->start) < 0)
			res = 1;
	}
	for (z = zb; z < ze; z++)
		pthread_mutex_unlock(&z->mutex);

	return res;
}

/*
 * Reset zbd_info.write_cnt, the counter that counts down towards the next
 * zone reset.
 */
static void zbd_reset_write_cnt(const struct thread_data *td,
				const struct fio_file *f)
{
	assert(0 <= td->o.zrf.u.f && td->o.zrf.u.f <= 1);

	pthread_mutex_lock(&f->zbd_info->mutex);
	f->zbd_info->write_cnt = td->o.zrf.u.f ?
		min(1.0 / td->o.zrf.u.f, 0.0 + UINT_MAX) : UINT_MAX;
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
		zbd_reset_write_cnt(td, f);
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

	zb = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];
	ze = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset +
						  f->io_size)];
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

	swd = zbd_process_swd(f, SET_SWD);
	dprint(FD_ZBD, "%s(%s): swd = %" PRIu64 "\n", __func__, f->file_name,
	       swd);
}

void zbd_file_reset(struct thread_data *td, struct fio_file *f)
{
	struct fio_zone_info *zb, *ze;
	uint32_t zone_idx_e;

	if (!f->zbd_info)
		return;

	zb = &f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];
	zone_idx_e = zbd_zone_idx(f, f->file_offset + f->io_size);
	ze = &f->zbd_info->zone_info[zone_idx_e];
	zbd_init_swd(f);
	/*
	 * If data verification is enabled reset the affected zones before
	 * writing any data to avoid that a zone reset has to be issued while
	 * writing data, which causes data loss.
	 */
	zbd_reset_zones(td, f, zb, ze, td->o.verify != VERIFY_NONE &&
			(td->o.td_ddir & TD_DDIR_WRITE) &&
			td->runstate != TD_VERIFYING);
	zbd_reset_write_cnt(td, f);
}

/* The caller must hold f->zbd_info->mutex. */
static bool is_zone_open(const struct thread_data *td, const struct fio_file *f,
			 unsigned int zone_idx)
{
	struct zoned_block_device_info *zbdi = f->zbd_info;
	int i;

	assert(td->o.max_open_zones <= ARRAY_SIZE(zbdi->open_zones));
	assert(zbdi->num_open_zones <= td->o.max_open_zones);

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
static bool zbd_open_zone(struct thread_data *td, const struct io_u *io_u,
			  uint32_t zone_idx)
{
	const uint32_t min_bs = td->o.min_bs[DDIR_WRITE];
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z = &f->zbd_info->zone_info[zone_idx];
	bool res = true;

	if (z->cond == BLK_ZONE_COND_OFFLINE)
		return false;

	/*
	 * Skip full zones with data verification enabled because resetting a
	 * zone causes data loss and hence causes verification to fail.
	 */
	if (td->o.verify != VERIFY_NONE && zbd_zone_full(f, z, min_bs))
		return false;

	/* Zero means no limit */
	if (!td->o.max_open_zones)
		return true;

	pthread_mutex_lock(&f->zbd_info->mutex);
	if (is_zone_open(td, f, zone_idx))
		goto out;
	res = false;
	if (f->zbd_info->num_open_zones >= td->o.max_open_zones)
		goto out;
	dprint(FD_ZBD, "%s: opening zone %d\n", f->file_name, zone_idx);
	f->zbd_info->open_zones[f->zbd_info->num_open_zones++] = zone_idx;
	z->open = 1;
	res = true;

out:
	pthread_mutex_unlock(&f->zbd_info->mutex);
	return res;
}

/* The caller must hold f->zbd_info->mutex */
static void zbd_close_zone(struct thread_data *td, const struct fio_file *f,
			   unsigned int open_zone_idx)
{
	uint32_t zone_idx;

	assert(open_zone_idx < f->zbd_info->num_open_zones);
	zone_idx = f->zbd_info->open_zones[open_zone_idx];
	memmove(f->zbd_info->open_zones + open_zone_idx,
		f->zbd_info->open_zones + open_zone_idx + 1,
		(FIO_MAX_OPEN_ZBD_ZONES - (open_zone_idx + 1)) *
		sizeof(f->zbd_info->open_zones[0]));
	f->zbd_info->num_open_zones--;
	f->zbd_info->zone_info[zone_idx].open = 0;
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
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z;
	unsigned int open_zone_idx = -1;
	uint32_t zone_idx, new_zone_idx;
	int i;

	assert(is_valid_offset(f, io_u->offset));

	if (td->o.max_open_zones) {
		/*
		 * This statement accesses f->zbd_info->open_zones[] on purpose
		 * without locking.
		 */
		zone_idx = f->zbd_info->open_zones[(io_u->offset -
						    f->file_offset) *
				f->zbd_info->num_open_zones / f->io_size];
	} else {
		zone_idx = zbd_zone_idx(f, io_u->offset);
	}
	dprint(FD_ZBD, "%s(%s): starting from zone %d (offset %lld, buflen %lld)\n",
	       __func__, f->file_name, zone_idx, io_u->offset, io_u->buflen);

	/*
	 * Since z->mutex is the outer lock and f->zbd_info->mutex the inner
	 * lock it can happen that the state of the zone with index zone_idx
	 * has changed after 'z' has been assigned and before f->zbd_info->mutex
	 * has been obtained. Hence the loop.
	 */
	for (;;) {
		z = &f->zbd_info->zone_info[zone_idx];

		pthread_mutex_lock(&z->mutex);
		pthread_mutex_lock(&f->zbd_info->mutex);
		if (td->o.max_open_zones == 0)
			goto examine_zone;
		if (f->zbd_info->num_open_zones == 0) {
			pthread_mutex_unlock(&f->zbd_info->mutex);
			pthread_mutex_unlock(&z->mutex);
			dprint(FD_ZBD, "%s(%s): no zones are open\n",
			       __func__, f->file_name);
			return NULL;
		}
		open_zone_idx = (io_u->offset - f->file_offset) *
			f->zbd_info->num_open_zones / f->io_size;
		assert(open_zone_idx < f->zbd_info->num_open_zones);
		new_zone_idx = f->zbd_info->open_zones[open_zone_idx];
		if (new_zone_idx == zone_idx)
			break;
		zone_idx = new_zone_idx;
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);
	}

	/* Both z->mutex and f->zbd_info->mutex are held. */

examine_zone:
	if (z->wp + min_bs <= (z+1)->start) {
		pthread_mutex_unlock(&f->zbd_info->mutex);
		goto out;
	}
	dprint(FD_ZBD, "%s(%s): closing zone %d\n", __func__, f->file_name,
	       zone_idx);
	if (td->o.max_open_zones)
		zbd_close_zone(td, f, open_zone_idx);
	pthread_mutex_unlock(&f->zbd_info->mutex);

	/* Only z->mutex is held. */

	/* Zone 'z' is full, so try to open a new zone. */
	for (i = f->io_size / f->zbd_info->zone_size; i > 0; i--) {
		zone_idx++;
		pthread_mutex_unlock(&z->mutex);
		z++;
		if (!is_valid_offset(f, z->start)) {
			/* Wrap-around. */
			zone_idx = zbd_zone_idx(f, f->file_offset);
			z = &f->zbd_info->zone_info[zone_idx];
		}
		assert(is_valid_offset(f, z->start));
		pthread_mutex_lock(&z->mutex);
		if (z->open)
			continue;
		if (zbd_open_zone(td, io_u, zone_idx))
			goto out;
	}

	/* Only z->mutex is held. */

	/* Check whether the write fits in any of the already opened zones. */
	pthread_mutex_lock(&f->zbd_info->mutex);
	for (i = 0; i < f->zbd_info->num_open_zones; i++) {
		zone_idx = f->zbd_info->open_zones[i];
		pthread_mutex_unlock(&f->zbd_info->mutex);
		pthread_mutex_unlock(&z->mutex);

		z = &f->zbd_info->zone_info[zone_idx];

		pthread_mutex_lock(&z->mutex);
		if (z->wp + min_bs <= (z+1)->start)
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

	if (!zbd_open_zone(td, io_u, z - f->zbd_info->zone_info)) {
		pthread_mutex_unlock(&z->mutex);
		z = zbd_convert_to_open_zone(td, io_u);
		assert(z);
	}

	if (z->verify_block * min_bs >= f->zbd_info->zone_size)
		log_err("%s: %d * %d >= %llu\n", f->file_name, z->verify_block,
			min_bs, (unsigned long long) f->zbd_info->zone_size);
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
	const struct fio_file *f = io_u->file;
	struct fio_zone_info *z1, *z2;
	const struct fio_zone_info *const zf =
		&f->zbd_info->zone_info[zbd_zone_idx(f, f->file_offset)];

	/*
	 * Skip to the next non-empty zone in case of sequential I/O and to
	 * the nearest non-empty zone in case of random I/O.
	 */
	for (z1 = zb + 1, z2 = zb - 1; z1 < zl || z2 >= zf; z1++, z2--) {
		if (z1 < zl && z1->cond != BLK_ZONE_COND_OFFLINE) {
			pthread_mutex_lock(&z1->mutex);
			if (z1->start + min_bs <= z1->wp)
				return z1;
			pthread_mutex_unlock(&z1->mutex);
		} else if (!td_random(td)) {
			break;
		}
		if (td_random(td) && z2 >= zf &&
		    z2->cond != BLK_ZONE_COND_OFFLINE) {
			pthread_mutex_lock(&z2->mutex);
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
 * zbd_queue_io - update the write pointer of a sequential zone
 * @io_u: I/O unit
 * @success: Whether or not the I/O unit has been queued successfully
 * @q: queueing status (busy, completed or queued).
 *
 * For write and trim operations, update the write pointer of the I/O unit
 * target zone.
 */
static void zbd_queue_io(struct io_u *io_u, int q, bool success)
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

	if (z->type != BLK_ZONE_TYPE_SEQWRITE_REQ)
		return;

	if (!success)
		goto unlock;

	dprint(FD_ZBD,
	       "%s: queued I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zone_idx);

	switch (io_u->ddir) {
	case DDIR_WRITE:
		zone_end = min((uint64_t)(io_u->offset + io_u->buflen),
			       (z + 1)->start);
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
static void zbd_put_io(const struct io_u *io_u)
{
	const struct fio_file *f = io_u->file;
	struct zoned_block_device_info *zbd_info = f->zbd_info;
	struct fio_zone_info *z;
	uint32_t zone_idx;

	if (!zbd_info)
		return;

	zone_idx = zbd_zone_idx(f, io_u->offset);
	assert(zone_idx < zbd_info->nr_zones);
	z = &zbd_info->zone_info[zone_idx];

	if (z->type != BLK_ZONE_TYPE_SEQWRITE_REQ)
		return;

	dprint(FD_ZBD,
	       "%s: terminate I/O (%lld, %llu) for zone %u\n",
	       f->file_name, io_u->offset, io_u->buflen, zone_idx);

	assert(pthread_mutex_unlock(&z->mutex) == 0);
	zbd_check_swd(f);
}

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
	zone_idx = zbd_zone_idx(f, f->last_pos[ddir]);
	z = &f->zbd_info->zone_info[zone_idx];

	if (td->zone_bytes >= td->o.zone_size ||
	    f->last_pos[ddir] >= (z+1)->start ||
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
	const struct fio_file *f = io_u->file;
	uint32_t zone_idx_b;
	struct fio_zone_info *zb, *zl, *orig_zb;
	uint32_t orig_len = io_u->buflen;
	uint32_t min_bs = td->o.min_bs[io_u->ddir];
	uint64_t new_len;
	int64_t range;

	if (!f->zbd_info)
		return io_u_accept;

	assert(is_valid_offset(f, io_u->offset));
	assert(io_u->buflen);
	zone_idx_b = zbd_zone_idx(f, io_u->offset);
	zb = &f->zbd_info->zone_info[zone_idx_b];
	orig_zb = zb;

	/* Accept the I/O offset for conventional zones. */
	if (zb->type == BLK_ZONE_TYPE_CONVENTIONAL)
		return io_u_accept;

	/*
	 * Accept the I/O offset for reads if reading beyond the write pointer
	 * is enabled.
	 */
	if (zb->cond != BLK_ZONE_COND_OFFLINE &&
	    io_u->ddir == DDIR_READ && td->o.read_beyond_wp)
		return io_u_accept;

	zbd_check_swd(f);

	/*
	 * Lock the io_u target zone. The zone will be unlocked if io_u offset
	 * is changed or when io_u completes and zbd_put_io() executed.
	 * To avoid multiple jobs doing asynchronous I/Os from deadlocking each
	 * other waiting for zone locks when building an io_u batch, first
	 * only trylock the zone. If the zone is already locked by another job,
	 * process the currently queued I/Os so that I/O progress is made and
	 * zones unlocked.
	 */
	if (pthread_mutex_trylock(&zb->mutex) != 0) {
		if (!td_ioengine_flagged(td, FIO_SYNCIO))
			io_u_quiesce(td);
		pthread_mutex_lock(&zb->mutex);
	}

	switch (io_u->ddir) {
	case DDIR_READ:
		if (td->runstate == TD_VERIFYING) {
			zb = zbd_replay_write_order(td, io_u, zb);
			goto accept;
		}
		/*
		 * Check that there is enough written data in the zone to do an
		 * I/O of at least min_bs B. If there isn't, find a new zone for
		 * the I/O.
		 */
		range = zb->cond != BLK_ZONE_COND_OFFLINE ?
			zb->wp - zb->start : 0;
		if (range < min_bs ||
		    ((!td_random(td)) && (io_u->offset + min_bs > zb->wp))) {
			pthread_mutex_unlock(&zb->mutex);
			zl = &f->zbd_info->zone_info[zbd_zone_idx(f,
						f->file_offset + f->io_size)];
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
		if (!zbd_open_zone(td, io_u, zone_idx_b)) {
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
			      (zb + 1)->start - io_u->offset);
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
			((zb + 1)->start - io_u->offset),
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
	assert(zb->cond != BLK_ZONE_COND_OFFLINE);
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
