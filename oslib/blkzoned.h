/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */
#ifndef FIO_BLKZONED_H
#define FIO_BLKZONED_H

#include "zbd_types.h"

#ifdef CONFIG_HAS_BLKZONED
extern int blkzoned_get_zoned_model(struct thread_data *td,
			struct fio_file *f, enum zbd_zoned_model *model);
extern int blkzoned_report_zones(struct thread_data *td,
				struct fio_file *f, uint64_t offset,
				struct zbd_zone *zones, unsigned int nr_zones);
extern int blkzoned_reset_wp(struct thread_data *td, struct fio_file *f,
				uint64_t offset, uint64_t length);
extern int blkzoned_move_zone_wp(struct thread_data *td, struct fio_file *f,
				 struct zbd_zone *z, uint64_t length,
				 const char *buf);
extern int blkzoned_get_max_open_zones(struct thread_data *td, struct fio_file *f,
				       unsigned int *max_open_zones);
extern int blkzoned_get_max_active_zones(struct thread_data *td,
					 struct fio_file *f,
					 unsigned int *max_active_zones);
extern int blkzoned_finish_zone(struct thread_data *td, struct fio_file *f,
				uint64_t offset, uint64_t length);
#else
/*
 * Define stubs for systems that do not have zoned block device support.
 */
static inline int blkzoned_get_zoned_model(struct thread_data *td,
			struct fio_file *f, enum zbd_zoned_model *model)
{
	/*
	 * If this is a block device file, allow zbd emulation.
	 */
	if (f->filetype == FIO_TYPE_BLOCK) {
		*model = ZBD_NONE;
		return 0;
	}

	return -ENODEV;
}
static inline int blkzoned_report_zones(struct thread_data *td,
				struct fio_file *f, uint64_t offset,
				struct zbd_zone *zones, unsigned int nr_zones)
{
	return -EIO;
}
static inline int blkzoned_reset_wp(struct thread_data *td, struct fio_file *f,
				    uint64_t offset, uint64_t length)
{
	return -EIO;
}
static inline int blkzoned_move_zone_wp(struct thread_data *td,
					struct fio_file *f, struct zbd_zone *z,
					uint64_t length, const char *buf)
{
	return -EIO;
}
static inline int blkzoned_get_max_open_zones(struct thread_data *td, struct fio_file *f,
					      unsigned int *max_open_zones)
{
	return -EIO;
}
static inline int blkzoned_get_max_active_zones(struct thread_data *td,
						struct fio_file *f,
						unsigned int *max_open_zones)
{
	return -EIO;
}
static inline int blkzoned_finish_zone(struct thread_data *td,
				       struct fio_file *f,
				       uint64_t offset, uint64_t length)
{
	return -EIO;
}
#endif

#endif /* FIO_BLKZONED_H */
