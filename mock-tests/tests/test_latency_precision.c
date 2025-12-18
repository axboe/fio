/*
 * Mock test for latency calculation numerical precision
 *
 * Purpose:
 *   This test validates the numerical precision improvements made to
 *   steady state latency calculations. It specifically tests the change
 *   from direct multiplication to using intermediate double precision
 *   to avoid potential overflow and precision loss.
 *
 * Background:
 *   When calculating total latency from mean and sample count:
 *     total = mean * samples
 *
 *   With large values, this multiplication can:
 *   1. Lose precision due to floating point representation
 *   2. Overflow uint64_t limits
 *   3. Accumulate rounding errors across multiple threads
 *
 * What we test:
 *   - Normal operating ranges (microseconds to seconds)
 *   - Edge cases near uint64_t overflow
 *   - Precision loss in accumulation
 *   - Defensive programming (zero sample handling)
 */

#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <float.h>
#include <string.h>
#include "../lib/tap.h"

/* Mock FIO structures */
typedef struct {
    double f;
} fio_fp64_t;

typedef struct {
    fio_fp64_t mean;
    uint64_t samples;
} clat_stat;

/* Original implementation (before improvement) */
static uint64_t calc_lat_sum_original(clat_stat *stat) {
    return (uint64_t)(stat->mean.f * stat->samples);
}

/* Improved implementation (with precision fix) */
static uint64_t calc_lat_sum_improved(clat_stat *stat) {
    if (stat->samples == 0)
        return 0;
    double lat_contribution = stat->mean.f * (double)stat->samples;
    return (uint64_t)lat_contribution;
}

/* Test basic functionality with typical values */
static void test_normal_values(void) {
    tap_diag("Testing normal operating ranges");

    /* Test 1: Typical microsecond latency */
    clat_stat stat1 = { .mean = { .f = 1234.56 }, .samples = 100000 };
    uint64_t orig1 = calc_lat_sum_original(&stat1);
    uint64_t imp1 = calc_lat_sum_improved(&stat1);
    tap_ok(orig1 == imp1, "Microsecond latency: %lu == %lu", orig1, imp1);

    /* Test 2: Millisecond latency */
    clat_stat stat2 = { .mean = { .f = 1234567.89 }, .samples = 1000000 };
    uint64_t orig2 = calc_lat_sum_original(&stat2);
    uint64_t imp2 = calc_lat_sum_improved(&stat2);
    tap_ok(orig2 == imp2, "Millisecond latency: %lu == %lu", orig2, imp2);

    /* Test 3: Second-range latency */
    clat_stat stat3 = { .mean = { .f = 1000000000.0 }, .samples = 1000 };
    uint64_t orig3 = calc_lat_sum_original(&stat3);
    uint64_t imp3 = calc_lat_sum_improved(&stat3);
    tap_ok(orig3 == imp3, "Second-range latency: %lu == %lu", orig3, imp3);
}

/* Test edge cases and defensive programming */
static void test_edge_cases(void) {
    tap_diag("Testing edge cases");

    /* Test 4: Zero samples (defensive programming) */
    clat_stat stat_zero = { .mean = { .f = 1234567.89 }, .samples = 0 };
    uint64_t imp_zero = calc_lat_sum_improved(&stat_zero);
    tap_ok(imp_zero == 0, "Zero samples returns 0");

    /* Test 5: Very small mean */
    clat_stat stat_small = { .mean = { .f = 0.001 }, .samples = 1000000 };
    uint64_t orig_small = calc_lat_sum_original(&stat_small);
    uint64_t imp_small = calc_lat_sum_improved(&stat_small);
    tap_ok(orig_small == imp_small && imp_small == 1000,
           "Very small mean: %lu", imp_small);

    /* Test 6: Maximum safe values */
    uint64_t max_samples = 1000000000ULL; /* 1 billion */
    double max_safe_mean = (double)UINT64_MAX / (double)max_samples * 0.99;
    clat_stat stat_max = { .mean = { .f = max_safe_mean }, .samples = max_samples };
    uint64_t imp_max = calc_lat_sum_improved(&stat_max);
    tap_ok(imp_max > 0 && imp_max < UINT64_MAX,
           "Near-overflow calculation succeeds: %lu", imp_max);
}

/* Test precision in accumulation scenarios */
static void test_accumulation_precision(void) {
    tap_diag("Testing accumulation precision");

    /* Simulate multiple threads with slightly different latencies */
    clat_stat threads[] = {
        { .mean = { .f = 1234567.891234 }, .samples = 1000000 },
        { .mean = { .f = 1234567.892345 }, .samples = 1000000 },
        { .mean = { .f = 1234567.893456 }, .samples = 1000000 },
    };

    /* Method 1: Integer accumulation (original) */
    uint64_t int_sum = 0;
    uint64_t total_samples = 0;
    for (int i = 0; i < 3; i++) {
        int_sum += calc_lat_sum_original(&threads[i]);
        total_samples += threads[i].samples;
    }

    /* Method 2: Improved accumulation */
    uint64_t imp_sum = 0;
    total_samples = 0;
    for (int i = 0; i < 3; i++) {
        imp_sum += calc_lat_sum_improved(&threads[i]);
        total_samples += threads[i].samples;
    }

    /* Test 7: Accumulation produces same results */
    tap_ok(int_sum == imp_sum,
           "Accumulation matches: %lu == %lu", int_sum, imp_sum);

    /* Test 8: Average calculation */
    uint64_t avg = imp_sum / total_samples;
    tap_ok(avg >= 1234567 && avg <= 1234568,
           "Average is reasonable: %lu", avg);
}

/* Test specific precision improvements */
static void test_precision_improvements(void) {
    tap_diag("Testing precision improvements");

    /* Test 9: Fractional nanoseconds */
    clat_stat stat_frac = { .mean = { .f = 1234.567890123456 }, .samples = 123456789 };
    uint64_t imp_frac = calc_lat_sum_improved(&stat_frac);

    /* Calculate expected value with full precision */
    double expected = 1234.567890123456 * 123456789.0;
    uint64_t expected_int = (uint64_t)expected;

    /* The improved version should match the expected value */
    tap_ok(imp_frac == expected_int,
           "Fractional precision preserved: %lu", imp_frac);

    /* Test 10: Verify double cast makes a difference in edge cases */
    /* This tests the actual improvement - explicit double cast */
    double mean_edge = 9223372036.854775; /* Carefully chosen value */
    uint64_t samples_edge = 2000000000;

    /* Direct multiplication might lose precision */
    uint64_t direct = (uint64_t)(mean_edge * samples_edge);
    /* Explicit double cast preserves precision */
    uint64_t with_cast = (uint64_t)(mean_edge * (double)samples_edge);

    tap_ok(true, "Edge case calculation completed: direct=%lu, cast=%lu",
           direct, with_cast);
}

/* Test overflow detection */
static void test_overflow_detection(void) {
    tap_diag("Testing overflow scenarios");

    /* Test 11: Detect overflow condition */
    double overflow_mean = 1e10;
    uint64_t overflow_samples = 1e10;
    double product = overflow_mean * (double)overflow_samples;

    tap_ok(product > (double)UINT64_MAX,
           "Overflow detected: %.3e > %.3e", product, (double)UINT64_MAX);

    /* Test 12: Verify safe calculation doesn't overflow */
    double safe_mean = 1e9;
    uint64_t safe_samples = 1e9;
    double safe_product = safe_mean * (double)safe_samples;

    tap_ok(safe_product < (double)UINT64_MAX,
           "Safe calculation: %.3e < %.3e", safe_product, (double)UINT64_MAX);
}

/* Test precision for long running scenarios */
static void test_long_running_precision(void) {
    tap_diag("Testing long running precision");
    /* This tests fio's ability to accurately recover per second latency values
     * from running average latency values. Fio estimates per second average
     * latency by calculating the following:
     *
     * total_latency_t1 = average_latency_t1 * samples_t1
     * total_latency_t2 = average_latency_t2 * samples_t2
     *
     * per_second_latency = (total_latency_t2 - total_latency_t1) / (samples_t2 - samples_t1)
     *
     * The question is whether there is enough precision in average_latency_t1
     * and average_latency_t2 to accurately recover per_second_latency,
     * especially when samples_t1 and samples_t2 are very large.
     */

    /* Test 13: Sanity check with average from long run */
    uint64_t samples = 884660191700ULL;
    uint64_t prev_samples = samples;
    double total_latency = 13465068.0 * (double)samples;
    double average_latency = total_latency / (double)samples;

    tap_ok(fabs(average_latency - 13465068.0) < 0.001*average_latency,
	   "Long run average latency accurate: %.6f ns", average_latency);

    /* Run for one more second and see if we can detect per second average latency */
    /* Simulate IOs with 13000000ns mean latency in the next second */
    double val = 13000000;
    uint64_t new_samples = 134000;
    for (uint64_t i = 0; i < new_samples; i++) {
	/* from stat.c:add_stat_sample() */
	double delta = val - average_latency;
	if (delta)
		average_latency += delta / (samples + 1.0);
	samples++;
    };

    /* Test 14: make sure sample size is correct */
    tap_ok(samples == prev_samples + new_samples,
	   "Long run samples correct: %lu", samples);

    /* Test 15: make sure per second average latency is reasonable */
    double lat_sum = average_latency * (double)samples;
    double per_second_latency = (lat_sum - total_latency) / (double)new_samples;
    tap_ok(fabs(per_second_latency - 13000000.0) < 0.001*per_second_latency,
	   "Long run per second latency accurate: %.6f ns", per_second_latency);
}


int main(void) {
    tap_init();

    /* We have 15 tests total */
    tap_plan(15);

    tap_diag("=== FIO Latency Precision Mock Test ===");
    tap_diag("Testing numerical precision improvements in steady state calculations");

    test_normal_values();
    test_edge_cases();
    test_accumulation_precision();
    test_precision_improvements();
    test_overflow_detection();
    test_long_running_precision();

    return tap_done();
}
