/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 */

#ifndef FIO_SPRANDOM_H
#define FIO_SPRANDOM_H

/**
 * struct sprandom_info - information for sprandom operations.
 *
 * @over_provisioning:  Over-provisioning ratio for the flash device.
 * @region_sz:          Size of each region in bytes.
 * @num_regions:        Number of SPRandom regions.
 * @validity_dist:      validity for each region.
 */
struct sprandom_info {
	double    over_provisioning;
	uint64_t  region_sz;
	uint32_t  num_regions;

	double    *validity_dist;
};

#endif /* FIO_SPRANDOM_H */
