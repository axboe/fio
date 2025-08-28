/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 */

#ifndef FIO_SPRANDOM_H
#define FIO_SPRANDOM_H

#include <stdint.h>
#include "lib/rand.h"
#include "pcbuf.h"

/**
 * struct sprandom_info - information for sprandom operations.
 *
 * @over_provisioning:  Over-provisioning ratio for the flash device.
 * @region_sz:          Size of each region in bytes.
 * @num_regions:        Number of SPRandom regions.
 * @validity_dist:      validity for each region.
 * @invalid_pct:        invalidation percentages per region.
 * @invalid_buf:        invalidation offsets two pahse buffer.
 * @invalid_capacity:   maximal size of invalidation buffer for a region.
 * @invalid_count:      number of invalid offsets in each phase.
 * @current_region:     index of the current region being processed.
 * @curr_phase:         current phase of the invalidation process (0 or 1).
 * @region_write_count: number of writes performed in the current region.
 * @writes_remaining:   umber of writes left to perform.
 * @rand_state:         state for the random number generator.
 */
struct sprandom_info {
	double    over_provisioning;
	uint64_t  region_sz;
	uint32_t  num_regions;

	uint32_t  *invalid_pct;

	/* Invalidation list*/
	struct pc_buf *invalid_buf;
	uint64_t invalid_capacity;
	size_t   invalid_count[2];
	uint32_t current_region;
	uint32_t curr_phase;

	/* Region and write tracking */
	uint64_t region_write_count;
	uint64_t writes_remaining;

	struct frand_state *rand_state;
};

/**
 * sprandom_init - Initialize the sprandom for a given file and thread.
 * @td: FIO thread data
 * @f: FIO file
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int sprandom_init(struct thread_data *td, struct fio_file *f);

/**
 * sprandom_free - Frees resources associated with a sprandom_info structure.
 * @info: sprandom_info structure to be freed.
 */
void sprandom_free(struct sprandom_info *info);

/**
 * sprandom_get_next_offset - Get the next random offset for a file.
 * @info: sprandom_info structure containing the state
 * @f: FIO file
 * @b: Output pointer to store the next offset.
 *
 * Returns 0 on success, or a negative error code on failure.
 */
int sprandom_get_next_offset(struct sprandom_info *info, struct fio_file *f, uint64_t *b);

#endif /* FIO_SPRANDOM_H */
