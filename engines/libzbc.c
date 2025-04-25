/*
 * Copyright (C) 2019 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 *
 * libzbc engine
 * IO engine using libzbc library to talk to SMR disks.
 */
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <libzbc/zbc.h>

#include "fio.h"
#include "err.h"
#include "zbd_types.h"
#include "zbd.h"

struct libzbc_data {
	struct zbc_device	*zdev;
	enum zbc_dev_model	model;
	uint64_t		nr_sectors;
	uint32_t		max_open_seq_req;
};

static int libzbc_get_dev_info(struct libzbc_data *ld, struct fio_file *f)
{
	struct zbc_device_info *zinfo;

	zinfo = calloc(1, sizeof(*zinfo));
	if (!zinfo)
		return -ENOMEM;

	zbc_get_device_info(ld->zdev, zinfo);
	ld->model = zinfo->zbd_model;
	ld->nr_sectors = zinfo->zbd_sectors;
	ld->max_open_seq_req = zinfo->zbd_max_nr_open_seq_req;

	dprint(FD_ZBD, "%s: vendor_id:%s, type: %s, model: %s\n",
	       f->file_name, zinfo->zbd_vendor_id,
	       zbc_device_type_str(zinfo->zbd_type),
	       zbc_device_model_str(zinfo->zbd_model));

	free(zinfo);

	return 0;
}

static int libzbc_open_dev(struct thread_data *td, struct fio_file *f,
			   struct libzbc_data **p_ld)
{
	struct libzbc_data *ld = td->io_ops_data;
	int ret, flags = OS_O_DIRECT;

	if (ld) {
		/* Already open */
		assert(ld->zdev);
		goto out;
	}

	if (f->filetype != FIO_TYPE_BLOCK && f->filetype != FIO_TYPE_CHAR) {
		td_verror(td, EINVAL, "wrong file type");
		log_err("ioengine libzbc only works on block or character devices\n");
		return -EINVAL;
	}

	if (td_write(td) || td_trim(td)) {
		if (!read_only)
			flags |= O_RDWR;
	} else if (td_read(td)) {
			flags |= O_RDONLY;
	}

	ld = calloc(1, sizeof(*ld));
	if (!ld)
		return -ENOMEM;

	ret = zbc_open(f->file_name,
		       flags | ZBC_O_DRV_SCSI | ZBC_O_DRV_ATA,
		       &ld->zdev);
	if (ret) {
		log_err("%s: zbc_open() failed, err=%d\n",
			f->file_name, ret);
		goto err;
	}

	ret = libzbc_get_dev_info(ld, f);
	if (ret)
		goto err_close;

	td->io_ops_data = ld;
out:
	if (p_ld)
		*p_ld = ld;

	return 0;

err_close:
	zbc_close(ld->zdev);
err:
	free(ld);
	return ret;
}

static int libzbc_close_dev(struct thread_data *td)
{
	struct libzbc_data *ld = td->io_ops_data;
	int ret = 0;

	td->io_ops_data = NULL;
	if (ld) {
		if (ld->zdev)
			ret = zbc_close(ld->zdev);
		free(ld);
	}

	return ret;
}
static int libzbc_open_file(struct thread_data *td, struct fio_file *f)
{
	return libzbc_open_dev(td, f, NULL);
}

static int libzbc_close_file(struct thread_data *td, struct fio_file *f)
{
	int ret;

	ret = libzbc_close_dev(td);
	if (ret)
		log_err("%s: close device failed err %d\n",
			f->file_name, ret);

	return ret;
}

static void libzbc_cleanup(struct thread_data *td)
{
	libzbc_close_dev(td);
}

static int libzbc_invalidate(struct thread_data *td, struct fio_file *f)
{
	/* Passthrough IO do not cache data. Nothing to do */
	return 0;
}

static int libzbc_get_file_size(struct thread_data *td, struct fio_file *f)
{
	struct libzbc_data *ld;
	int ret;

	if (fio_file_size_known(f))
		return 0;

	ret = libzbc_open_dev(td, f, &ld);
	if (ret)
		return ret;

	f->real_file_size = ld->nr_sectors << 9;
	fio_file_set_size_known(f);

	return 0;
}

static int libzbc_get_zoned_model(struct thread_data *td, struct fio_file *f,
				  enum zbd_zoned_model *model)
{
	struct libzbc_data *ld;
	int ret;

	if (f->filetype != FIO_TYPE_BLOCK && f->filetype != FIO_TYPE_CHAR)
		return -EINVAL;

	ret = libzbc_open_dev(td, f, &ld);
	if (ret)
		return ret;

	switch (ld->model) {
	case ZBC_DM_HOST_AWARE:
		*model = ZBD_HOST_AWARE;
		break;
	case ZBC_DM_HOST_MANAGED:
		*model = ZBD_HOST_MANAGED;
		break;
	default:
		*model = ZBD_NONE;
		break;
	}

	return 0;
}

static int libzbc_report_zones(struct thread_data *td, struct fio_file *f,
			       uint64_t offset, struct zbd_zone *zbdz,
			       unsigned int nr_zones)
{
	struct libzbc_data *ld;
	uint64_t sector = offset >> 9;
	struct zbc_zone *zones;
	unsigned int i;
	int ret;

	ret = libzbc_open_dev(td, f, &ld);
	if (ret)
		return ret;

	if (sector >= ld->nr_sectors)
		return 0;

	zones = calloc(nr_zones, sizeof(struct zbc_zone));
	if (!zones) {
		ret = -ENOMEM;
		goto out;
	}

	ret = zbc_report_zones(ld->zdev, sector, ZBC_RO_ALL, zones, &nr_zones);
	if (ret < 0) {
		log_err("%s: zbc_report_zones failed, err=%d\n",
			f->file_name, ret);
		goto out;
	}

	for (i = 0; i < nr_zones; i++, zbdz++) {
		zbdz->start = zones[i].zbz_start << 9;
		zbdz->len = zones[i].zbz_length << 9;
		zbdz->wp = zones[i].zbz_write_pointer << 9;
		/*
		 * ZBC/ZAC do not define zone capacity, so use the zone size as
		 * the zone capacity.
		 */
		zbdz->capacity = zbdz->len;

		switch (zones[i].zbz_type) {
		case ZBC_ZT_CONVENTIONAL:
			zbdz->type = ZBD_ZONE_TYPE_CNV;
			break;
		case ZBC_ZT_SEQUENTIAL_REQ:
			zbdz->type = ZBD_ZONE_TYPE_SWR;
			break;
		case ZBC_ZT_SEQUENTIAL_PREF:
			zbdz->type = ZBD_ZONE_TYPE_SWP;
			break;
		default:
			td_verror(td, errno, "invalid zone type");
			log_err("%s: invalid type for zone at sector %llu.\n",
				f->file_name, (unsigned long long)zbdz->start);
			ret = -EIO;
			goto out;
		}

		switch (zones[i].zbz_condition) {
		case ZBC_ZC_NOT_WP:
			zbdz->cond = ZBD_ZONE_COND_NOT_WP;
			break;
		case ZBC_ZC_EMPTY:
			zbdz->cond = ZBD_ZONE_COND_EMPTY;
			break;
		case ZBC_ZC_IMP_OPEN:
			zbdz->cond = ZBD_ZONE_COND_IMP_OPEN;
			break;
		case ZBC_ZC_EXP_OPEN:
			zbdz->cond = ZBD_ZONE_COND_EXP_OPEN;
			break;
		case ZBC_ZC_CLOSED:
			zbdz->cond = ZBD_ZONE_COND_CLOSED;
			break;
		case ZBC_ZC_FULL:
			zbdz->cond = ZBD_ZONE_COND_FULL;
			break;
		case ZBC_ZC_RDONLY:
		case ZBC_ZC_OFFLINE:
		default:
			/* Treat all these conditions as offline (don't use!) */
			zbdz->cond = ZBD_ZONE_COND_OFFLINE;
			zbdz->wp = zbdz->start;
		}
	}

	ret = nr_zones;
out:
	free(zones);
	return ret;
}

static int libzbc_reset_wp(struct thread_data *td, struct fio_file *f,
			   uint64_t offset, uint64_t length)
{
	struct libzbc_data *ld = td->io_ops_data;
	uint64_t sector = offset >> 9;
	uint64_t end_sector = (offset + length) >> 9;
	unsigned int nr_zones;
	struct zbc_errno err;
	int i, ret;

	assert(ld);
	assert(ld->zdev);

	nr_zones = (length + td->o.zone_size - 1) / td->o.zone_size;
	if (!sector && end_sector >= ld->nr_sectors) {
		/* Reset all zones */
		ret = zbc_reset_zone(ld->zdev, 0, ZBC_OP_ALL_ZONES);
		if (ret)
			goto err;

		return 0;
	}

	for (i = 0; i < nr_zones; i++, sector += td->o.zone_size >> 9) {
		ret = zbc_reset_zone(ld->zdev, sector, 0);
		if (ret)
			goto err;
	}

	return 0;

err:
	zbc_errno(ld->zdev, &err);
	td_verror(td, errno, "zbc_reset_zone failed");
	if (err.sk)
		log_err("%s: reset wp failed %s:%s\n",
			f->file_name,
			zbc_sk_str(err.sk), zbc_asc_ascq_str(err.asc_ascq));
	return -ret;
}

static int libzbc_move_zone_wp(struct thread_data *td, struct fio_file *f,
			       struct zbd_zone *z, uint64_t length,
			       const char *buf)
{
	struct libzbc_data *ld = td->io_ops_data;
	uint64_t sector = z->wp >> 9;
	size_t count = length >> 9;
	struct zbc_errno err;
	int ret;

	assert(ld);
	assert(ld->zdev);
	assert(buf);

	ret = zbc_pwrite(ld->zdev, buf, count, sector);
	if (ret == count)
		return 0;

	zbc_errno(ld->zdev, &err);
	td_verror(td, errno, "zbc_write for write pointer move failed");
	if (err.sk)
		log_err("%s: wp move failed %s:%s\n",
			f->file_name,
			zbc_sk_str(err.sk), zbc_asc_ascq_str(err.asc_ascq));
	return -ret;
}

static int libzbc_finish_zone(struct thread_data *td, struct fio_file *f,
			      uint64_t offset, uint64_t length)
{
	struct libzbc_data *ld = td->io_ops_data;
	uint64_t sector = offset >> 9;
	unsigned int nr_zones;
	struct zbc_errno err;
	int i, ret;

	assert(ld);
	assert(ld->zdev);

	nr_zones = (length + td->o.zone_size - 1) / td->o.zone_size;
	assert(nr_zones > 0);

	for (i = 0; i < nr_zones; i++, sector += td->o.zone_size >> 9) {
		ret = zbc_finish_zone(ld->zdev, sector, 0);
		if (ret)
			goto err;
	}

	return 0;

err:
	zbc_errno(ld->zdev, &err);
	td_verror(td, errno, "zbc_finish_zone failed");
	if (err.sk)
		log_err("%s: finish zone failed %s:%s\n",
			f->file_name,
			zbc_sk_str(err.sk), zbc_asc_ascq_str(err.asc_ascq));
	return -ret;
}

static int libzbc_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				     unsigned int *max_open_zones)
{
	struct libzbc_data *ld;
	int ret;

	ret = libzbc_open_dev(td, f, &ld);
	if (ret)
		return ret;

	if (ld->max_open_seq_req == ZBC_NO_LIMIT)
		*max_open_zones = 0;
	else
		*max_open_zones = ld->max_open_seq_req;

	return 0;
}

ssize_t libzbc_rw(struct thread_data *td, struct io_u *io_u)
{
	struct libzbc_data *ld = td->io_ops_data;
	struct fio_file *f = io_u->file;
	uint64_t sector = io_u->offset >> 9;
	size_t count = io_u->xfer_buflen >> 9;
	struct zbc_errno err;
	ssize_t ret;

	if (io_u->ddir == DDIR_WRITE)
		ret = zbc_pwrite(ld->zdev, io_u->xfer_buf, count, sector);
	else
		ret = zbc_pread(ld->zdev, io_u->xfer_buf, count, sector);
	if (ret == count)
		return ret;

	if (ret > 0) {
		log_err("Short %s, len=%zu, ret=%zd\n",
			io_u->ddir == DDIR_READ ? "read" : "write",
			count << 9, ret << 9);
		return -EIO;
	}

	/* I/O error */
	zbc_errno(ld->zdev, &err);
	td_verror(td, errno, "libzbc i/o failed");
	if (err.sk) {
		log_err("%s: op %u offset %llu+%llu failed (%s:%s), err %zd\n",
			f->file_name, io_u->ddir,
			io_u->offset, io_u->xfer_buflen,
			zbc_sk_str(err.sk),
			zbc_asc_ascq_str(err.asc_ascq), ret);
	} else {
		log_err("%s: op %u offset %llu+%llu failed, err %zd\n",
			f->file_name, io_u->ddir,
			io_u->offset, io_u->xfer_buflen, ret);
	}

	return -EIO;
}

static enum fio_q_status libzbc_queue(struct thread_data *td, struct io_u *io_u)
{
	struct libzbc_data *ld = td->io_ops_data;
	struct fio_file *f = io_u->file;
	ssize_t ret = 0;

	fio_ro_check(td, io_u);

	dprint(FD_ZBD, "%p:%s: libzbc queue %llu\n",
	       td, f->file_name, io_u->offset);

	if (io_u->ddir == DDIR_READ || io_u->ddir == DDIR_WRITE) {
		ret = libzbc_rw(td, io_u);
	} else if (ddir_sync(io_u->ddir)) {
		ret = zbc_flush(ld->zdev);
		if (ret)
			log_err("zbc_flush error %zd\n", ret);
	} else if (io_u->ddir == DDIR_TRIM) {
		ret = zbd_do_io_u_trim(td, io_u);
		if (!ret)
			ret = EINVAL;
	} else {
		log_err("Unsupported operation %u\n", io_u->ddir);
		ret = -EINVAL;
	}
	if (ret < 0)
		io_u->error = -ret;

	return FIO_Q_COMPLETED;
}

FIO_STATIC struct ioengine_ops ioengine = {
	.name			= "libzbc",
	.version		= FIO_IOOPS_VERSION,
	.open_file		= libzbc_open_file,
	.close_file		= libzbc_close_file,
	.cleanup		= libzbc_cleanup,
	.invalidate		= libzbc_invalidate,
	.get_file_size		= libzbc_get_file_size,
	.get_zoned_model	= libzbc_get_zoned_model,
	.report_zones		= libzbc_report_zones,
	.reset_wp		= libzbc_reset_wp,
	.move_zone_wp		= libzbc_move_zone_wp,
	.get_max_open_zones	= libzbc_get_max_open_zones,
	.finish_zone		= libzbc_finish_zone,
	.queue			= libzbc_queue,
	.flags			= FIO_SYNCIO | FIO_NOEXTEND | FIO_RAWIO,
};

static void fio_init fio_libzbc_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_libzbc_unregister(void)
{
	unregister_ioengine(&ioengine);
}
