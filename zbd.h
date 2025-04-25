/*
 * Copyright (C) 2018 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */

#ifndef FIO_ZBD_H
#define FIO_ZBD_H

#include "io_u.h"
#include "ioengines.h"
#include "oslib/blkzoned.h"
#include "zbd_types.h"

struct fio_file;

enum io_u_action {
	io_u_accept	= 0,
	io_u_eof	= 1,
	io_u_completed  = 2,
};

/**
 * struct fio_zone_info - information about a single ZBD zone
 * @start: zone start location (bytes)
 * @wp: zone write pointer location (bytes)
 * @capacity: maximum size usable from the start of a zone (bytes)
 * @writes_in_flight: number of writes in flight fo the zone
 * @max_write_error_offset: maximum offset from zone start among the failed
 *                          writes to the zone
 * @mutex: protects the modifiable members in this structure
 * @type: zone type (BLK_ZONE_TYPE_*)
 * @cond: zone state (BLK_ZONE_COND_*)
 * @has_wp: whether or not this zone can have a valid write pointer
 * @write: whether or not this zone is the write target at this moment. Only
 *              relevant if zbd->max_open_zones > 0.
 * @reset_zone: whether or not this zone should be reset before writing to it
 * @fixing_zone_wp: whether or not the write pointer of this zone is under fix
 */
struct fio_zone_info {
	pthread_mutex_t		mutex;
	uint64_t		start;
	uint64_t		wp;
	uint64_t		capacity;
	uint32_t		writes_in_flight;
	uint32_t		max_write_error_offset;
	enum zbd_zone_type	type:2;
	enum zbd_zone_cond	cond:4;
	unsigned int		has_wp:1;
	unsigned int		write:1;
	unsigned int		reset_zone:1;
	unsigned int		fixing_zone_wp:1;
};

/**
 * zoned_block_device_info - zoned block device characteristics
 * @model: Device model.
 * @max_write_zones: global limit on the number of sequential write zones which
 *      are simultaneously written. A zero value means unlimited zones of
 *      simultaneous writes and that write target zones will not be tracked in
 *      the write_zones array.
 * @max_active_zones: device side limit on the number of sequential write zones
 *	in open or closed conditions. A zero value means unlimited number of
 *	zones in the conditions.
 * @mutex: Protects the modifiable members in this structure (refcount and
 *		num_open_zones).
 * @zone_size: size of a single zone in bytes.
 * @wp_valid_data_bytes: total size of data in zones with write pointers
 * @write_min_zone: Minimum zone index of all job's write ranges. Inclusive.
 * @write_max_zone: Maximum zone index of all job's write ranges. Exclusive.
 * @zone_size_log2: log2 of the zone size in bytes if it is a power of 2 or 0
 *		if the zone size is not a power of 2.
 * @nr_zones: number of zones
 * @refcount: number of fio files that share this structure
 * @num_write_zones: number of write target zones
 * @write_cnt: Number of writes since the latest zone reset triggered by
 *	       the zone_reset_frequency fio job parameter.
 * @write_zones: zone numbers of write target zones
 * @zone_info: description of the individual zones
 *
 * Only devices for which all zones have the same size are supported.
 * Note: if the capacity is not a multiple of the zone size then the last zone
 * will be smaller than 'zone_size'.
 */
struct zoned_block_device_info {
	enum zbd_zoned_model	model;
	uint32_t		max_write_zones;
	uint32_t		max_active_zones;
	pthread_mutex_t		mutex;
	uint64_t		zone_size;
	uint64_t		wp_valid_data_bytes;
	uint32_t		write_min_zone;
	uint32_t		write_max_zone;
	uint32_t		zone_size_log2;
	uint32_t		nr_zones;
	uint32_t		refcount;
	uint32_t		num_write_zones;
	uint32_t		write_cnt;
	uint32_t		write_zones[ZBD_MAX_WRITE_ZONES];
	struct fio_zone_info	zone_info[0];
};

int zbd_init_files(struct thread_data *td);
void zbd_recalc_options_with_zone_granularity(struct thread_data *td);
int zbd_setup_files(struct thread_data *td);
void zbd_free_zone_info(struct fio_file *f);
void zbd_file_reset(struct thread_data *td, struct fio_file *f);
bool zbd_unaligned_write(int error_code);
void setup_zbd_zone_mode(struct thread_data *td, struct io_u *io_u);
enum fio_ddir zbd_adjust_ddir(struct thread_data *td, struct io_u *io_u,
			      enum fio_ddir ddir);
enum io_u_action zbd_adjust_block(struct thread_data *td, struct io_u *io_u);
char *zbd_write_status(const struct thread_stat *ts);
int zbd_do_io_u_trim(struct thread_data *td, struct io_u *io_u);
void zbd_log_err(const struct thread_data *td, const struct io_u *io_u);
void zbd_recover_write_error(struct thread_data *td, struct io_u *io_u);

static inline void zbd_close_file(struct fio_file *f)
{
	if (f->zbd_info)
		zbd_free_zone_info(f);
}

static inline void zbd_queue_io_u(struct thread_data *td, struct io_u *io_u,
				  enum fio_q_status *status)
{
	if (io_u->zbd_queue_io) {
		io_u->zbd_queue_io(td, io_u, (int *)status);
		io_u->zbd_queue_io = NULL;
	}
}

static inline void zbd_put_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (io_u->zbd_put_io) {
		io_u->zbd_put_io(td, io_u);
		io_u->zbd_queue_io = NULL;
		io_u->zbd_put_io = NULL;
	}
}

#endif /* FIO_ZBD_H */
