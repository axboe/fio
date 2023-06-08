/*
 * Copyright (C) 2020 Western Digital Corporation or its affiliates.
 *
 * This file is released under the GPL.
 */
#ifndef FIO_ZBD_TYPES_H
#define FIO_ZBD_TYPES_H

#include <inttypes.h>

#define ZBD_MAX_WRITE_ZONES	4096

/*
 * Zoned block device models.
 */
enum zbd_zoned_model {
	ZBD_NONE		= 0x1,	/* No zone support. Emulate zones. */
	ZBD_HOST_AWARE		= 0x2,	/* Host-aware zoned block device */
	ZBD_HOST_MANAGED	= 0x3,	/* Host-managed zoned block device */
};

/*
 * Zone types.
 */
enum zbd_zone_type {
	ZBD_ZONE_TYPE_CNV	= 0x1,	/* Conventional */
	ZBD_ZONE_TYPE_SWR	= 0x2,	/* Sequential write required */
	ZBD_ZONE_TYPE_SWP	= 0x3,	/* Sequential write preferred */
};

/*
 * Zone conditions.
 */
enum zbd_zone_cond {
        ZBD_ZONE_COND_NOT_WP    = 0x0,
        ZBD_ZONE_COND_EMPTY     = 0x1,
        ZBD_ZONE_COND_IMP_OPEN  = 0x2,
        ZBD_ZONE_COND_EXP_OPEN  = 0x3,
        ZBD_ZONE_COND_CLOSED    = 0x4,
        ZBD_ZONE_COND_READONLY  = 0xD,
        ZBD_ZONE_COND_FULL      = 0xE,
        ZBD_ZONE_COND_OFFLINE   = 0xF,
};

/*
 * Zone descriptor.
 */
struct zbd_zone {
	uint64_t		start;
	uint64_t		wp;
	uint64_t		len;
	uint64_t		capacity;
	enum zbd_zone_type	type;
	enum zbd_zone_cond	cond;
};

#endif /* FIO_ZBD_TYPES_H */
