/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 */
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include "fio.h"
#include "file.h"
#include "sprandom.h"

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

	log_buf(&out, "[");
	for (i = 0; i < len - 1; i++) {
		log_buf(&out, "%.2f, ", darray[i]);
	}
	log_buf(&out, "%.2f]\n", darray[len - 1]);
	if (hdr) {
		dprint(FD_SPRANDOM, "%s: ", hdr);
	}
	dprint(FD_SPRANDOM, "%s", out.buf);
	buf_output_free(&out);
}

static void print_d_points(struct point *parray, size_t len)
{
	struct buf_output out;
	unsigned int i;

	buf_output_init(&out);

	log_buf(&out, "[");
	for (i = 0; i < len - 1; i++) {
		log_buf(&out, "(%.2f %.2f), ", parray[i].x, parray[i].y);
	}
	log_buf(&out, "(%.2f %.2f)]\n", parray[len - 1].x, parray[len - 1].y);
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

static void reverse(double arr[], size_t size)
{

	size_t left = 0;
	size_t right = size - 1;

	if (size <= 1) {
		return;
	}

	while (left < right) {
		double temp = arr[left];
		arr[left] = arr[right];
		arr[right] = temp;
		left++;
		right--;
	}
}

static double *linspace(double start, double end, unsigned int num)
{
	double *arr;
	unsigned int i;
	double step;

	if (num == 0) {
		return NULL;
	}

	dprint(FD_SPRANDOM, "linespace start=%0.2f end=%0.2f num=%d\n",
			start, end, num);

	arr = d_alloc(num);
	if (arr == NULL) {
		return NULL;
	}

	if (num == 1) {
		arr[0] = start;
		return arr;
	}

	/* Calculate step size */
	step = (end - start) / ((double)num - 1.0);

	for (i = 0; i < num; i++) {
		arr[i] = start + (double)i * step;
	}

	return arr;
}

static double linear_interp(double new_x, const double *x_arr,
			    const double *y_arr, unsigned int num)
{
	unsigned int i;
	double x1, y1, x2, y2;

	if (num == 0) {
		return 0.0;
	}

	if (num == 1) {
		return y_arr[0]; /* If only one point, return its y-value */
	}

	/* Handle extrapolation outside the range */
	if (new_x <= x_arr[0]) {
		return y_arr[0];
	}

	if (new_x >= x_arr[num - 1]) {
		return y_arr[num - 1];
	}

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
			if (fabs(x2 - x1) < 1e-9) {
				return y1;
			}

			return y1 + (y2 - y1) * ((new_x - x1) / (x2 - x1));
		}
	}
	/* Should not reach here if new_x is within bounds
	 * and x_arr is strictly increasing
	 */
	return 0.0;
}

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

	if (points == NULL || resampled_points == NULL) {
		return -3;
	}

	if (num == 0) {
		log_err("Original points array cannot be empty.\n");
		return -3;
	}

	if (num_resampled == 0) {
		*resampled_points = NULL;
		return 0;
	}

	qsort(points, num, sizeof(struct point), compare_points);

	/* Check if x-values are strictly increasing and sort them */
	for (i = 0; i < num - 1; i++) {
		if (points[i+1].x <= points[i].x) {
			log_err("x-values must be strictly increasing.\n");
			ret = -2;
			goto cleanup;
		}
	}

	/* 2. Extract x and y into separate arrays for interpolation */
	x_orig = d_alloc(num);
	y_orig = d_alloc(num);
	if (x_orig == NULL || y_orig == NULL) {
		log_err("Memory allocation failed for x_orig or y_orig.\n");
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
		log_err("Memory allocation failed for new_points_arr.\n");
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

/* compute write amplification */
static inline double compute_waf(double over_provisioning)
{
	return 0.5 / over_provisioning + 0.7;
}

static inline double compute_validity(double waf)
{
	return 1.0 - (double)1.0 / waf;
}

static double *compute_validity_dist(unsigned int n_regions, double over_provisioning)
{
	double waf = compute_waf(over_provisioning);
	double validity = compute_validity(waf);
	double *validity_distribution = NULL;
	double *blocks_ratio = NULL;
	double *acc_ratio = NULL;
	double acc;
	unsigned int i;
	struct point *points = NULL;
	struct point *points_resampled = NULL;
	int ret;

	if (n_regions == 0) {
		log_err("Error: requires at least one region");
		goto out;
	}

	validity_distribution = linspace(1.0, validity, n_regions);

	blocks_ratio = d_alloc(n_regions);
	if (blocks_ratio == NULL) {
		log_err("Memory allocation failed for linspace.\n");
		goto out;
	}

	for (i = 0; i < n_regions; i++) {
		blocks_ratio[i] = 1.0 / validity_distribution[i];
	}

	acc_ratio = d_alloc(n_regions);
	if (acc_ratio == NULL) {
		log_err("Memory allocation failed for linspace_c.\n");
		goto out;
	}

	acc = 0.0;
	for (i = 0; i < n_regions; i++) {
		acc_ratio[i] = acc + blocks_ratio[i];
		acc = acc_ratio[i];
	}

	print_d_array("validity_distribution", validity_distribution, n_regions);
	print_d_array("blocks ration", blocks_ratio, n_regions);
	print_d_array("accumulated ratio:", acc_ratio, n_regions);

	points = p_alloc(n_regions);

	for (i = 0; i < n_regions; i++) {
		points[i].x = acc_ratio[i];
		points[i].y = validity_distribution[i];
	}
	print_d_points(points, n_regions);

	ret = sample_curve_equally_on_x(points, n_regions, n_regions,
					&points_resampled);

	if (ret == 0) {
		print_d_points(points_resampled, n_regions);
	} else {
		log_err("Failed to resample curve. Error code: %d\n", ret);
		free(validity_distribution);
		validity_distribution = NULL;
		goto out;
	}

	for (i = 0; i < n_regions; i++) {
		validity_distribution[i] = points_resampled[i].y;
	}
	print_d_array("validity resampled", validity_distribution, n_regions);

out:
	free(points);
	free(points_resampled);
	free(blocks_ratio);
	free(acc_ratio);

	reverse(validity_distribution, n_regions);

	return validity_distribution;
}

static uint64_t sprandom_pysical_size(double over_provisioning, uint64_t logical_sz)
{
	return logical_sz + ceil((double)logical_sz * over_provisioning);
}

int sprandom_setup(struct sprandom_info *spr_info, uint64_t logical_size, uint64_t align_bs)
{
	double over_provisioning = spr_info->over_provisioning;
	uint64_t physical_size = sprandom_pysical_size(over_provisioning,
						       logical_size);
	uint64_t region_sz;
	size_t total_alloc = 0;

	double *validity_dist = compute_validity_dist(spr_info->num_regions,
						      spr_info->over_provisioning);
	if (!validity_dist)
		return -ENOMEM;

	/* Initialize validity_distribution */
	print_d_array("validity resampled:", validity_dist, spr_info->num_regions);

	spr_info->validity_dist = validity_dist;
	total_alloc += spr_info->num_regions * sizeof(spr_info->validity_dist[0]);

	/* Precompute invalidity percentage array */
	region_sz = physical_size / spr_info->num_regions;

	spr_info->region_sz = region_sz;

	return 0;
}
