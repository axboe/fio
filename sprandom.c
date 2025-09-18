/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 */
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "lib/pow2.h"
#include "fio.h"
#include "file.h"
#include "sprandom.h"

/*
 * Model for Estimating Steady-State Data Distribution in SSDs
 *
 * This model estimates the distribution of valid data across a flash drive
 * in a steady state. It is based on the key insight from Desnoyers' research,
 * which establishes a relationship between data validity and the physical
 * space it occupies.
 *
 * P. Desnoyers, "Analytic Models of SSD Write Performance,"
 * ACM Transactions on Storage,
 * vol. 8, no. 2, pp. 1–18, Jun. 2012, doi: 10.1145/2133360.2133364.
 *
 * The Core Principle
 * ==================
 *
 * The fundamental concept is that for a drive in a steady state, the product
 * of a block's validity and the fraction of drive space occupied by such
 * blocks is constant.
 *
 * Key Equation (1): i * f(i) = k
 *
 * Where:
 * - i: The number of valid pages in a block.
 * - f(i): The fraction of the drive composed of blocks with 'i' valid pages.
 * - k: A constant for the drive.
 *
 * This implies that for any two validity levels i and j: i * f(i) = j * f(j).
 * In other words, regions with lower validity (more invalid data) must
 * occupy proportionally more physical space than regions with high validity.
 *
 *
 * Modeling Steps
 * ==============
 * The model is built by following these steps:
 *
 * 1. Normalize Validity & Relate to Write Amplification (WA)
 * We normalize 'i' into a validity fraction:
 *
 *      valid_frac(i) = i / num_pages_per_region
 *
 * A greedy garbage collection (GC) algorithm reclaims the block with the
 * lowest validity. The validity of this GC block (`valid_frac_gc`) is
 * determined by the drive's WA:
 *
 *      valid_frac_gc = 1 - (1 / WA)
 *
 * 2. Determine Write Amplification (WA) from Over-Provisioning (OP)
 * The WA can be calculated from the drive's OP. A simple approximation
 * is often sufficient for most cases:
 *
 *      WA ≈ 0.5 / OP + 0.7
 *
 * Note: The precise formula from Desnoyers uses
 *      alpha = T/U
 * where
 *      OP = alpha - 1
 *
 * in the equation:
 *                   alpha
 *      WA = ----------------------------
 *           (alpha + W(-alpha*e^-alpha)
 *
 * with W being the Lambert W function).
 *
 * 3. Define the Distribution Curve
 *
 * Using the steady-state principle, we can find the relative size f(i) of a
 * region given its validity (`valid_frac_i`) by comparing it to the GC block.
 *
 *       valid_frac(i) * f(i) = valid_frac_gc * f_gc
 *
 * By defining the base size f_gc = 1, we get a simple relationship:
 *
 *       f(i) = valid_frac_gc / valid_frac(i)
 *
 * This formula defines a curve where points are spaced equally by validity.
 *
 * 4. Resample for Equal-Sized Regions
 *
 * The final step is to make the model practical. We take the curve defined
 * above and resample it to get points that are equally spaced by region
 * size f(i). This resampling gives the expected validity for each
 * equal-sized region of the drive, completing the model.
 */

#define PCT_PRECISION 10000

static inline double *d_alloc(size_t n)
{
	return calloc(n, sizeof(double));
}

struct point {
	double x;
	double y;
};

static inline struct point *p_alloc(size_t n)
{
	return calloc(n, sizeof(struct point));
}

static void print_d_array(const char *hdr, double *darray, size_t len)
{
	struct buf_output out;
	int i;

	buf_output_init(&out);

	__log_buf(&out, "[");
	for (i = 0; i < len - 1; i++)
		__log_buf(&out, "%.2f, ", darray[i]);

	__log_buf(&out, "%.2f]\n", darray[len - 1]);
	if (hdr)
		dprint(FD_SPRANDOM, "%s: ", hdr);

	dprint(FD_SPRANDOM, "%s", out.buf);
	buf_output_free(&out);
}

static void print_d_points(struct point *parray, size_t len)
{
	struct buf_output out;
	unsigned int i;

	buf_output_init(&out);

	__log_buf(&out, "[");
	for (i = 0; i < len - 1; i++)
		__log_buf(&out, "(%.2f %.2f), ", parray[i].x, parray[i].y);

	__log_buf(&out, "(%.2f %.2f)]\n", parray[len - 1].x, parray[len - 1].y);
	dprint(FD_SPRANDOM, "%s", out.buf);
	buf_output_free(&out);
}

/* Comparison function for qsort to sort points by x-value */
static int compare_points(const void *a, const void *b)
{
	/* Cast void pointers to struct point pointers */
	const struct point *point_a = (const struct point *)a;
	const struct point *point_b = (const struct point *)b;

	if (point_a->x < point_b->x)
		return -1;

	if (point_a->x > point_b->x)
		return 1;

	return 0;
}

/**
 * reverse - Reverses the elements of a double array in place.
 * @arr: pointer to the array of doubles to be reversed.
 * @size: number of elements in the array.
 */
static void reverse(double arr[], size_t size)
{
	size_t left = 0;
	size_t right = size - 1;

	if (size <= 1)
		return;

	while (left < right) {
		double temp = arr[left];
		arr[left] = arr[right];
		arr[right] = temp;
		left++;
		right--;
	}
}

/**
 * linspace - Generates a linearly spaced array of doubles.
 * @start: The starting value of the sequence.
 * @end: The ending value of the sequence.
 * @num: The number of elements to generate.
 *
 * Allocates and returns an array of @num doubles, linearly spaced
 * between @start and @end (inclusive). If @num is 0, returns NULL.
 * If @num is 1, the array contains only @start.
 *
 * Return: allocated array, or NULL on allocation failure or if @num is 0.
 */
static double *linspace(double start, double end, unsigned int num)
{
	double *arr;
	unsigned int i;
	double step;

	if (num == 0)
		return NULL;

	dprint(FD_SPRANDOM, "linespace start=%0.2f end=%0.2f num=%d\n",
	       start, end, num);

	arr = d_alloc(num);
	if (arr == NULL)
		return NULL;

	if (num == 1) {
		arr[0] = start;
		return arr;
	}

	/* Calculate step size */
	step = (end - start) / ((double)num - 1.0);

	for (i = 0; i < num; i++)
		arr[i] = start + (double)i * step;

	return arr;
}

/**
 * linear_interp - Performs linear interpolation or extrapolation.
 * @new_x: The x-value at which to interpolate.
 * @x_arr: Array of x-values (must be sorted in strictly increasing order).
 * @y_arr: Array of y-values corresponding to x_arr.
 * @num: Number of points in x_arr and y_arr.
 *
 * Returns the interpolated y-value at new_x using linear interpolation
 * between the points in x_arr and y_arr. If new_x is outside the range
 * of x_arr, returns the nearest endpoint's y-value (extrapolation).
 * Handles edge cases for zero or one point, and avoids division by zero
 * if two x-values are nearly identical.
 */
static double linear_interp(double new_x, const double *x_arr,
			    const double *y_arr, unsigned int num)
{
	unsigned int i;
	double x1, y1, x2, y2;

	if (num == 0)
		return 0.0;

	if (num == 1)
		return y_arr[0]; /* If only one point, return its y-value */

	/* Handle extrapolation outside the range */
	if (new_x <= x_arr[0])
		return y_arr[0];

	if (new_x >= x_arr[num - 1])
		return y_arr[num - 1];

	/* Find the interval [x_arr[i], x_arr[i + 1]] that contains new_x */
	for (i = 0; i < num - 1; i++) {
		if (new_x >= x_arr[i] && new_x <= x_arr[i + 1]) {
			x1 = x_arr[i];
			y1 = y_arr[i];
			x2 = x_arr[i + 1];
			y2 = y_arr[i + 1];

			/* Avoid division by zero if x values are identical
			 * Using a small epsilon for float comparison
			 * Return y1 if x1 and x2 are almost identical
			 */
			if (fabs(x2 - x1) < 1e-9)
				return y1;

			return y1 + (y2 - y1) * ((new_x - x1) / (x2 - x1));
		}
	}
	/* Should not reach here if new_x is within bounds
	 * and x_arr is strictly increasing
	 */
	return 0.0;
}

/**
 * sample_curve_equally_on_x - Resamples a curve at equally spaced x-values.
 * @points: array of input points (must have strictly increasing x-values).
 * @num: Number of input points.
 * @num_resampled: number of points to resample to.
 * @resampled_points: An output array of resampled points.
 *
 * Sorts the input points by x-value, checks for strictly increasing x-values,
 * and generates a new set of points with x-values equally spaced between the
 * minimum and maximum x of the input. Uses linear interpolation to compute
 * corresponding y-values.
 * Note: The function allocates memory for the output array.
 *
 * Return: 0 on success, negative error code on failure.
 */
static int sample_curve_equally_on_x(struct point *points, unsigned int num,
				     unsigned int num_resampled,
				     struct point **resampled_points)
{
	double *x_orig = (double *)0;
	double *y_orig = (double *)0;
	double *new_x_arr = (double *)0;
	struct point *new_points_arr = (struct point *)0;
	unsigned int i;
	int ret = 0;

	if (points == NULL || resampled_points == NULL)
		return -EINVAL;

	if (num == 0) {
		log_err("fio: original points array cannot be empty.\n");
		return -EINVAL;
	}

	if (num_resampled == 0) {
		*resampled_points = NULL;
		return 0;
	}

	qsort(points, num, sizeof(struct point), compare_points);

	/* Check if x-values are strictly increasing and sort them */
	for (i = 0; i < num - 1; i++) {
		if (points[i+1].x <= points[i].x) {
			log_err("fio: x-values must be strictly increasing.\n");
			ret = -EINVAL;
			goto cleanup;
		}
	}

	/* 2. Extract x and y into separate arrays for interpolation */
	x_orig = d_alloc(num);
	y_orig = d_alloc(num);
	if (x_orig == NULL || y_orig == NULL) {
		log_err("fio: Memory allocation failed for x_orig or y_orig.\n");
		ret = -ENOMEM;
		goto cleanup;
	}
	for (i = 0; i < num; i++) {
		x_orig[i] = points[i].x;
		y_orig[i] = points[i].y;
	}

	/* 4. Generate new_x values using linspace */
	new_x_arr = linspace(x_orig[0], x_orig[num - 1], num_resampled);
	if (new_x_arr == NULL) {
		ret = -ENOMEM;
		goto cleanup;
	}

	/* 5. Allocate memory for new resampled points */
	new_points_arr = p_alloc(num_resampled);
	if (new_points_arr == NULL) {
		log_err("fio: Memory allocation failed for new_points_arr.\n");
		ret = -ENOMEM;
		goto cleanup;
	}

	/* 6. Perform linear interpolation for each new_x to get new_y */
	for (i = 0; i < num_resampled; i++) {
		new_points_arr[i].x = new_x_arr[i];
		new_points_arr[i].y = linear_interp(new_x_arr[i], x_orig, y_orig, num);
	}

	*resampled_points = new_points_arr;

cleanup:
	free(x_orig);
	free(y_orig);
	free(new_x_arr);

	return ret;
}

/**
 * compute_waf - Compute the write amplification factor (WAF)
 * @over_provisioning: The over-provisioning ratio (0 < over_provisioning < 1)
 *
 * write amplification approximation equation
 *
 *                   0.5
 *     WAF = ------------------ + 0.7
 *           over_provisioning
 *
 * Return: The computed write amplification factor as a double.
 */
static inline double compute_waf(double over_provisioning)
{
	return 0.5 / over_provisioning + 0.7;
}

/**
 * compute_gc_validity - validity of the block selected for GC (garbage collector)
 *
 * @waf: The Write Amplification Factor, must be greater than 1.0.
 *
 * Return: The computed gavalidity;
 */
static inline double compute_gc_validity(double waf)
{
	assert(waf > 1.0); /* Ensure WAF is greater than 1.0 */
	return 1.0 - (double)1.0 / waf;
}

/**
 * compute_validity_dist - Computes a resampled validity distribution for regions.
 * @n_regions: Number of regions to divide the distribution into.
 * @over_provisioning: Over-provisioning factor used to calculate WAF and validity.
 *
 * Calculates the validity distribution across a specified number of regions,
 * based on the write amplification factor (WAF) and over-provisioning.
 * Steps:
 * - Allocates and fills arrays for:
 *   - validity distribution
 *   - block ratios
 *   - accumulated ratios
 * - Constructs a set of points representing the curve.
 * - Resamples the curve to ensure equal spacing along the x-axis.
 * - Reverses the resulting validity distribution before returning.
 *
 * Note: The function allocates memory for the validity distribution array.
 *
 * Return: resampled and reversed validity distribution array or NULL on error.
 */
static double *compute_validity_dist(unsigned int n_regions, double over_provisioning)
{
	double waf = compute_waf(over_provisioning);
	double validity = compute_gc_validity(waf);
	double *validity_distribution = NULL;
	double *blocks_ratio = NULL;
	double *acc_ratio = NULL;
	double acc;
	unsigned int i;
	struct point *points = NULL;
	struct point *points_resampled = NULL;
	int ret;

	if (n_regions == 0) {
		log_err("fio: requires at least one region");
		goto out;
	}

	/*
	 * Use linspace to get equally distributed validity values,
	 * along the y-axis of the curve we want to generate.
	 */
	validity_distribution = linspace(1.0, validity, n_regions);

	blocks_ratio = d_alloc(n_regions);
	if (blocks_ratio == NULL) {
		log_err("fio: memory allocation failed for linspace.\n");
		goto out;
	}

	for (i = 0; i < n_regions; i++)
		blocks_ratio[i] = 1.0 / validity_distribution[i];

	acc_ratio = d_alloc(n_regions);
	if (acc_ratio == NULL) {
		log_err("fio: memory allocation failed for linspace_c.\n");
		goto out;
	}

	acc = 0.0;
	for (i = 0; i < n_regions; i++) {
		acc_ratio[i] = acc + blocks_ratio[i];
		acc = acc_ratio[i];
	}

	print_d_array("validity_distribution", validity_distribution, n_regions);
	print_d_array("blocks ratio", blocks_ratio, n_regions);
	print_d_array("accumulated ratio:", acc_ratio, n_regions);

	points = p_alloc(n_regions);

	for (i = 0; i < n_regions; i++) {
		points[i].x = acc_ratio[i];
		points[i].y = validity_distribution[i];
	}
	print_d_points(points, n_regions);

	/*
	 * Use linspace again to get uniformly distributed x-values,
	 * and then interpolate the curve to find the validity at those
	 * uniformly distributed x-values.
	 */
	ret = sample_curve_equally_on_x(points, n_regions, n_regions,
					&points_resampled);

	if (ret == 0) {
		print_d_points(points_resampled, n_regions);
	} else {
		log_err("fio: failed to resample curve. Error code: %d\n", ret);
		free(validity_distribution);
		validity_distribution = NULL;
		goto out;
	}

	for (i = 0; i < n_regions; i++)
		validity_distribution[i] = points_resampled[i].y;

	print_d_array("validity resampled", validity_distribution, n_regions);

out:
	free(points);
	free(points_resampled);
	free(blocks_ratio);
	free(acc_ratio);

	reverse(validity_distribution, n_regions);

	return validity_distribution;
}

/**
 * Calculate the physical size based on logical size and over-provisioning
 *
 * @over_provisioning:   over provisioning factor (e.g. 0.2 for 20%)
 * @logical_sz:          Logical size in bytes
 * @align_bs:            Block size for alignment in bytes
 *
 * return: Physical size in bytes, including over-provisioning and aligned to align_bs
 */
static uint64_t sprandom_physical_size(double over_provisioning, uint64_t logical_sz,
				       uint64_t align_bs)
{
	uint64_t size;

	size = logical_sz + ceil((double)logical_sz * over_provisioning);
	return (size + (align_bs - 1)) & ~(align_bs - 1);
}

/**
 * estimate_inv_capacity - Estimates the invalid capacity of a region.
 * @region_cnt: number of offsets in the region.
 * @validity: invalidation ration in the regions (between 0 and 1).
 *
 * Calculates the expected number of invalidion in regions, adding a margin
 * of 6 standard deviations to account for statistical variation.
 *
 * Returns: Estimated invalid capacity
 */
static uint64_t estimate_inv_capacity(uint64_t region_cnt, double validity)
{
	double sigma = sqrt((double)region_cnt * validity * (1.0 - validity));
	return (uint64_t)ceil(region_cnt * (1.0 - validity) + 6.0 * sigma);
}

/**
 * sprandom_setup - Initialize and configure sprandom_info structure.
 * @spr_info: Pointer to sprandom_info structure to be initialized.
 * @logical_size: Logical size of the storage region.
 * @align_bs: Alignment block size.
 *
 * Calculates physical size and region parameters based on logical size,
 * alignment, and over-provisioning. Allocates and initializes validity
 * distribution and invalid percentage arrays for regions. Precomputes
 * invalid buffer capacity and allocates buffer. Sets up region size,
 * write counts, and resets region/phase counters.
 *
 * Returns 0 on success, enagative value on failure.
 */
static int sprandom_setup(struct sprandom_info *spr_info, uint64_t logical_size,
			  uint64_t align_bs)
{
	double over_provisioning = spr_info->over_provisioning;
	uint64_t physical_size;
	uint64_t region_sz;
	uint64_t region_write_count;
	double *validity_dist;
	size_t invalid_capacity;
	size_t total_alloc = 0;
	char bytes2str_buf[40];
	int i;

	physical_size = sprandom_physical_size(over_provisioning,
					       logical_size, align_bs);

	validity_dist = compute_validity_dist(spr_info->num_regions,
					      spr_info->over_provisioning);
	if (!validity_dist)
		return -ENOMEM;

	/* Initialize validity_distribution */
	print_d_array("validity resampled:", validity_dist, spr_info->num_regions);

	/* Precompute invalidity percentage array */
	spr_info->invalid_pct = calloc(spr_info->num_regions,
				       sizeof(spr_info->invalid_pct[0]));
	if (!spr_info->invalid_pct)
		goto err;

	total_alloc += spr_info->num_regions * sizeof(spr_info->invalid_pct[0]);

	for (i = 0; i < spr_info->num_regions; i++) {
		double inv = (1.0 - validity_dist[i]) * (double)PCT_PRECISION;
		spr_info->invalid_pct[i] = (int)round(inv);
	}

	region_sz = physical_size / spr_info->num_regions;
	region_write_count = region_sz / align_bs;

	invalid_capacity = estimate_inv_capacity(region_write_count,
						 validity_dist[0]);
	spr_info->invalid_capacity = invalid_capacity;

	spr_info->invalid_buf = pcb_alloc(invalid_capacity);

	total_alloc += invalid_capacity * sizeof(uint64_t);

	spr_info->region_sz = region_sz;
	spr_info->invalid_count[0] = 0;
	spr_info->invalid_count[1] = 0;
	spr_info->curr_phase = 0;
	spr_info->current_region = 0;
	spr_info->region_write_count = region_write_count;
	spr_info->writes_remaining = region_write_count;

	/* Display overall allocation */
	dprint(FD_SPRANDOM, "Summary:\n");
	dprint(FD_SPRANDOM, "  logical_size:      %"PRIu64": %s\n",
		logical_size,
		bytes2str_simple(bytes2str_buf, sizeof(bytes2str_buf), logical_size));
	dprint(FD_SPRANDOM, "  physical_size:     %"PRIu64": %s\n",
		physical_size,
		bytes2str_simple(bytes2str_buf, sizeof(bytes2str_buf), physical_size));
	dprint(FD_SPRANDOM, "  op: %02f\n", spr_info->over_provisioning);
	dprint(FD_SPRANDOM, "  region_size:        %"PRIu64"\n", region_sz);
	dprint(FD_SPRANDOM, "  num_regions:        %u\n", spr_info->num_regions);
	dprint(FD_SPRANDOM, "  region_write_count: %"PRIu64"\n", region_write_count);
	dprint(FD_SPRANDOM, "  invalid_capacity:   %zu\n", invalid_capacity);
	dprint(FD_SPRANDOM, "  dynamic memory:     %zu: %s\n",
		total_alloc,
		bytes2str_simple(bytes2str_buf, sizeof(bytes2str_buf), total_alloc));

	free(validity_dist);
	return 0;
err:
	free(validity_dist);
	free(spr_info->invalid_pct);
	return -ENOMEM;
}

/**
 * sprandom_add_with_probability - Adds an offset to the invalid buffer with
 * a probability.
 *
 * @info: sprandom_info structure containing random state and buffers.
 * @offset: The offset value to potentially add to the invalid buffer.
 * @phase: The current phase index for invalid count tracking.
 *
 * Generates a random value and, based on the current region's invalid percentage,
 * decides whether to add the offset to the invalid buffer.
 * If the buffer is full, ogs an error and asserts failure.
 */
static void sprandom_add_with_probability(struct sprandom_info *info,
					  uint64_t offset, unsigned int phase)
{

	int v = rand_between(info->rand_state, 0, PCT_PRECISION);

	if (v <= info->invalid_pct[info->current_region]) {
		if (pcb_space_available(info->invalid_buf)) {
			pcb_push_staged(info->invalid_buf, offset);
			info->invalid_count[phase]++;
		} else {
			dprint(FD_SPRANDOM, "pcb buffer would be overriten\n");
			assert(false);
		}
	}
}

static void dprint_invalidation(const struct sprandom_info *info)
{
	uint32_t phase = info->curr_phase;
	double inv = 0;
	double inv_act; /* actually invalidation percentage */

	inv_act = (double)info->invalid_count[phase] / (double)info->region_write_count;
	if (info->current_region > 0)
		inv = (double)info->invalid_pct[info->current_region - 1] / PCT_PRECISION;

	dprint(FD_SPRANDOM, "Invalidation[%d] %"PRIu64" %zu %.04f %.04f\n",
		info->current_region,
		info->region_write_count,
		info->invalid_count[phase],
		inv, inv_act);
}

/**
 * sprandom_get_next_offset - Generate the next write offset for a region,
 * managing invalidation, and region transitions.
 *
 * @info: sprandom_info structure containing state and configuration.
 * @f: fio file associated with the ssd device.
 * @b: block offset to store the next write offset.
 *
 * Generates offsets to write a region and saves a fraction of the offsets
 * in a two phase circular buffer.
 * When transitioning to the next region (phase is flipped),it first writes
 * all saved offsets to achieve the desired fraction of invalid blocks in the
 * previous region. The remainder of the current region is then filled with
 * new offsets.
 *
 * Returns:
 *   0 if a valid offset is found and stored in @b,
 *   1 if no more offsets are available (end of regions or LFSR exhausted).
 */
int sprandom_get_next_offset(struct sprandom_info *info, struct fio_file *f, uint64_t *b)
{
	uint64_t offset = 0;
	uint32_t phase = info->curr_phase;

	/* replay invalidation */
	if (pcb_pop(info->invalid_buf, &offset)) {
		sprandom_add_with_probability(info, offset,  phase ^ 1);
		dprint(FD_SPRANDOM, "Write %"PRIu64" over %d\n",
		       offset, info->current_region);
		goto out;
	}

	/* Move to next region */
	if (info->writes_remaining == 0) {
		if (info->current_region >= info->num_regions) {
			dprint(FD_SPRANDOM, "End: Last Region %d cur%d\n",
			       info->current_region, info->num_regions);
			return 1;
		}

		dprint_invalidation(info);

		info->invalid_count[phase] = 0;

		info->current_region++;
		phase ^= 1;
		info->writes_remaining = info->region_write_count -
						info->invalid_count[phase];
		info->curr_phase = phase;
		pcb_commit(info->invalid_buf);
	}

	/* Fetch new offset */
	if (lfsr_next(&f->lfsr, &offset)) {
		dprint(FD_SPRANDOM, "End: LFSR exhausted %d [%zu] [%zu]\n",
			info->current_region,
			info->invalid_count[phase],
			info->invalid_count[phase ^ 1]);

		dprint_invalidation(info);

		return 1;
	}

	if (info->writes_remaining > 0)
		info->writes_remaining--;

	sprandom_add_with_probability(info, offset,  phase ^ 1);
	dprint(FD_SPRANDOM, "Write %"PRIu64" lfsr %d\n", offset, info->current_region);
out:
	*b = offset;
	return 0;
}

/**
 * sprandom_init - initialize sprandom info
 * @td: fio thread data
 * @f: fio file associated with the ssd device.
 *
 * Sets up the sprandom_info structure for the given file according:
 * region count, over-provisioning, and file/device size.
 *
 * Return: 0 on success, negative error code on failure.
 */
int sprandom_init(struct thread_data *td, struct fio_file *f)
{
	struct sprandom_info *info = NULL;
	double over_provisioning;
	uint64_t logical_size;
	uint64_t align_bs = td->o.bs[DDIR_WRITE];
	int ret;

	if (!td->o.sprandom)
		return 0;

	if (!is_power_of_2(align_bs)) {
		log_err("fio: sprandom: bs [%"PRIu64"] should be power of 2",
			align_bs);
		return -EINVAL;
	}

	info = calloc(1, sizeof(*info));
	if (!info)
		return -ENOMEM;

	logical_size = min(f->real_file_size, f->io_size);
	over_provisioning = td->o.spr_over_provisioning.u.f;
	info->num_regions = td->o.spr_num_regions;
	info->over_provisioning = over_provisioning;
	td->o.io_size = sprandom_physical_size(over_provisioning,
					       logical_size, align_bs);
	info->rand_state = &td->sprandom_state;
	ret = sprandom_setup(info, logical_size, align_bs);
	if (ret)
		goto err;

	f->spr_info = info;
	return 0;
err:
	free(info);
	return ret;
}

/**
 * sprandom_free - Frees resources associated with a sprandom_info structure.
 * @info: Pointer to the sprandom_info structure to be freed.
 *
 * Releases memory allocated for validity_dist, invalid_buf, and the spr_info
 * structure itself. Does nothing if @spr_info is NULL.
 */
void sprandom_free(struct sprandom_info *info)
{
	if (!info)
		return;

	free(info->invalid_pct);
	free(info->invalid_buf);
	free(info);
}
