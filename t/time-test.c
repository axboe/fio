/*
 * Carry out arithmetic to explore conversion of CPU clock ticks to nsec
 *
 * When we use the CPU clock for timing, we do the following:
 *
 * 1) Calibrate the CPU clock to relate the frequency of CPU clock ticks
 *    to actual time.
 *
 *    Using gettimeofday() or clock_gettime(), count how many CPU clock
 *    ticks occur per usec
 *
 * 2) Calculate conversion factors so that we can ultimately convert
 *    from clocks ticks to nsec with
 *      nsec = (ticks * clock_mult) >> clock_shift
 *
 *    This is equivalent to
 *	nsec = ticks * (MULTIPLIER / cycles_per_nsec) / MULTIPLIER
 *    where
 *	clock_mult = MULTIPLIER / cycles_per_nsec
 *      MULTIPLIER = 2^clock_shift
 *
 *    It would be simpler to just calculate nsec = ticks / cycles_per_nsec,
 *    but all of this is necessary because of rounding when calculating
 *    cycles_per_nsec. With a 3.0GHz CPU, cycles_per_nsec would simply
 *    be 3. But with a 3.33GHz CPU or a 4.5GHz CPU, the fractional
 *    portion is lost with integer arithmetic.
 *
 *    This multiply and shift calculation also has a performance benefit
 *    as multiplication and bit shift operations are faster than integer
 *    division.
 *
 * 3) Dynamically determine clock_shift and clock_mult at run time based
 *    on MAX_CLOCK_SEC and cycles_per_usec. MAX_CLOCK_SEC is the maximum
 *    duration for which the conversion will be valid.
 *
 *    The primary constraint is that (ticks * clock_mult) must not overflow
 *    when ticks is at its maximum value.
 *
 *    So we have
 *	max_ticks = MAX_CLOCK_SEC * 1000000000 * cycles_per_nsec
 *	max_ticks * clock_mult <= ULLONG_MAX
 *	max_ticks * MULTIPLIER / cycles_per_nsec <= ULLONG_MAX
 *      MULTIPLIER <= ULLONG_MAX * cycles_per_nsec / max_ticks
 *
 *    Then choose the largest clock_shift that satisfies
 *	2^clock_shift <= ULLONG_MAX * cycles_per_nsec / max_ticks
 *
 *    Finally calculate the appropriate clock_mult associated with clock_shift
 *	clock_mult = 2^clock_shift / cycles_per_nsec
 *
 * 4) In the code below we have cycles_per_usec and use
 *	cycles_per_nsec = cycles_per_usec / 1000
 *
 *
 * The code below implements 4 clock tick to nsec conversion strategies
 *
 *   i) 64-bit arithmetic for the (ticks * clock_mult) product with the
 *	conversion valid for at most MAX_CLOCK_SEC
 *
 *  ii) NOT IMPLEMENTED Use 64-bit integers to emulate 128-bit multiplication
 *	for the (ticks * clock_mult) product
 *
 * iii) 64-bit arithmetic with clock ticks to nsec conversion occurring in
 *	two stages. The first stage counts the number of discrete, large chunks
 *	of time that have elapsed. To this is added the time represented by
 *	the remaining clock ticks. The advantage of this strategy is better
 *	accuracy because the (ticks * clock_mult) product used for final
 *	fractional chunk
 *
 *  iv) 64-bit arithmetic with the clock ticks to nsec conversion occuring in
 *	two stages. This is carried out using locks to update the number of
 *	large time chunks (MAX_CLOCK_SEC_2STAGE) that have elapsed.
 *
 *   v) 128-bit arithmetic used for the clock ticks to nsec conversion.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <assert.h>
#include <stdlib.h>
#include "lib/seqlock.h"

#define DEBUG 0
#define MAX_CLOCK_SEC 365*24*60*60ULL
#define MAX_CLOCK_SEC_2STAGE 60*60ULL
#define dprintf(...) if (DEBUG) { printf(__VA_ARGS__); }

enum {
	__CLOCK64_BIT		= 1 << 0,
	__CLOCK128_BIT		= 1 << 1,
	__CLOCK_MULT_SHIFT	= 1 << 2,
	__CLOCK_EMULATE_128	= 1 << 3,
	__CLOCK_2STAGE		= 1 << 4,
	__CLOCK_LOCK		= 1 << 5,

	CLOCK64_MULT_SHIFT	= __CLOCK64_BIT | __CLOCK_MULT_SHIFT,
	CLOCK64_EMULATE_128	= __CLOCK64_BIT | __CLOCK_EMULATE_128,
	CLOCK64_2STAGE		= __CLOCK64_BIT | __CLOCK_2STAGE,
	CLOCK64_LOCK		= __CLOCK64_BIT | __CLOCK_LOCK,
	CLOCK128_MULT_SHIFT	= __CLOCK128_BIT | __CLOCK_MULT_SHIFT,
};

static struct seqlock clock_seqlock;
static unsigned long long cycles_start;
static unsigned long long elapsed_nsec;

static unsigned int max_cycles_shift;
static unsigned long long max_cycles_mask;
static unsigned long long nsecs_for_max_cycles;

static unsigned int clock_shift;
static unsigned long long clock_mult;

static unsigned long long *nsecs;
static unsigned long long clock_mult64_128[2];
static __uint128_t clock_mult128;

/*
 * Functions for carrying out 128-bit
 * arithmetic using 64-bit integers
 *
 * 128-bit integers are stored as
 * arrays of two 64-bit integers
 *
 * Ordering is little endian
 *
 * a[0] has the less significant bits
 * a[1] has the more significant bits
 *
 * NOT FULLY IMPLEMENTED
 */
static void do_mult(unsigned long long a[2], unsigned long long b,
		    unsigned long long product[2])
{
	product[0] = product[1] = 0;
	return;
}

static void do_div(unsigned long long a[2], unsigned long long b,
		   unsigned long long c[2])
{
	return;
}

static void do_shift64(unsigned long long a[2], unsigned int count)
{
	a[0] = a[1] >> (count-64);
	a[1] = 0;
}

static void do_shift(unsigned long long a[2], unsigned int count)
{
	if (count > 64)
		do_shift64(a, count);
	else {
		while (count--) {
			a[0] >>= 1;
			a[0] |= a[1] << 63;
			a[1] >>= 1;
		}
	}
}

static void update_clock(unsigned long long t)
{
	write_seqlock_begin(&clock_seqlock);
	elapsed_nsec = (t >> max_cycles_shift) * nsecs_for_max_cycles;
	cycles_start = t & ~max_cycles_mask;
	write_seqlock_end(&clock_seqlock);
}

static unsigned long long _get_nsec(int mode, unsigned long long t)
{
	switch(mode) {
	case CLOCK64_MULT_SHIFT:
		return (t * clock_mult) >> clock_shift;
	case CLOCK64_EMULATE_128: {
		unsigned long long product[2] =  { };

		do_mult(clock_mult64_128, t, product);
		do_shift(product, clock_shift);
		return product[0];
		}
	case CLOCK64_2STAGE: {
		unsigned long long multiples, nsec;

		multiples = t >> max_cycles_shift;
		dprintf("multiples=%llu\n", multiples);
		nsec = multiples * nsecs_for_max_cycles;
		nsec += ((t & max_cycles_mask) * clock_mult) >> clock_shift;
		return nsec;
		}
	case CLOCK64_LOCK: {
		unsigned int seq;
		unsigned long long nsec;

		do {
			seq = read_seqlock_begin(&clock_seqlock);
			nsec = elapsed_nsec;
			nsec += ((t - cycles_start) * clock_mult) >> clock_shift;
		} while (read_seqlock_retry(&clock_seqlock, seq));
		return nsec;
		}
	case CLOCK128_MULT_SHIFT:
		return (unsigned long long)((t * clock_mult128) >> clock_shift);
		default:
			assert(0);
	}
}

static unsigned long long get_nsec(int mode, unsigned long long t)
{
	if (mode == CLOCK64_LOCK) {
		update_clock(t);
	}

	return _get_nsec(mode, t);
}

static void calc_mult_shift(int mode, void *mult, unsigned int *shift,
			    unsigned long long max_sec,
			    unsigned long long cycles_per_usec)
{
	unsigned long long max_ticks;
	max_ticks = max_sec * cycles_per_usec * 1000000ULL;

	switch (mode) {
	case CLOCK64_MULT_SHIFT: {
		unsigned long long max_mult, tmp;
		unsigned int sft = 0;

		/*
		 * Calculate the largest multiplier that will not
		 * produce a 64-bit overflow in the multiplication
		 * step of the clock ticks to nsec conversion
		 */
		max_mult = ULLONG_MAX / max_ticks;
		dprintf("max_ticks=%llu, __builtin_clzll=%d, max_mult=%llu\n", max_ticks, __builtin_clzll(max_ticks), max_mult);

		/*
		 * Find the largest shift count that will produce
		 * a multiplier less than max_mult
		 */
		tmp = max_mult * cycles_per_usec / 1000;
		while (tmp > 1) {
			tmp >>= 1;
			sft++;
			dprintf("tmp=%llu, sft=%u\n", tmp, sft);
		}

		*shift = sft;
		*((unsigned long long *)mult) = (unsigned long long) ((1ULL << sft) * 1000 / cycles_per_usec);
		break;
		}
	case CLOCK64_EMULATE_128: {
		unsigned long long max_mult[2], tmp[2] = { };
		unsigned int sft = 0;

		/*
		 * Calculate the largest multiplier that will not
		 * produce a 128-bit overflow in the multiplication
		 * step of the clock ticks to nsec conversion,
		 * but use only 64-bit integers in the process
		 */
		max_mult[0] = max_mult[1] = ULLONG_MAX;
		do_div(max_mult, max_ticks, max_mult);
		dprintf("max_ticks=%llu, __builtin_clzll=%d, max_mult=0x%016llx%016llx\n",
			max_ticks, __builtin_clzll(max_ticks), max_mult[1], max_mult[0]);

		/*
		 * Find the largest shift count that will produce
		 * a multiplier less than max_mult
		 */
		do_div(max_mult, cycles_per_usec, tmp);
		do_div(tmp, 1000ULL, tmp);
		while (tmp[0] > 1 || tmp[1] > 1) {
			do_shift(tmp, 1);
			sft++;
			dprintf("tmp=0x%016llx%016llx, sft=%u\n", tmp[1], tmp[0], sft);
		}

		*shift = sft;
//		*((unsigned long long *)mult) = (__uint128_t) (((__uint128_t)1 << sft) * 1000 / cycles_per_usec);
		break;
		}
	case CLOCK64_2STAGE: {
		unsigned long long tmp;
/*
 * This clock tick to nsec conversion requires two stages.
 *
 * Stage 1: Determine how many ~MAX_CLOCK_SEC_2STAGE periods worth of clock ticks
 * 	have elapsed and set nsecs to the appropriate value for those
 *	~MAX_CLOCK_SEC_2STAGE periods.
 * Stage 2: Subtract the ticks for the elapsed ~MAX_CLOCK_SEC_2STAGE periods from
 *	Stage 1. Convert remaining clock ticks to nsecs and add to previously
 *	set nsec value.
 *
 * To optimize the arithmetic operations, use the greatest power of 2 ticks
 * less than the number of ticks in MAX_CLOCK_SEC_2STAGE seconds.
 *
 */
		// Use a period shorter than MAX_CLOCK_SEC here for better accuracy
		calc_mult_shift(CLOCK64_MULT_SHIFT, mult, shift, MAX_CLOCK_SEC_2STAGE, cycles_per_usec);

		// Find the greatest power of 2 clock ticks that is less than the ticks in MAX_CLOCK_SEC_2STAGE
		max_cycles_shift = max_cycles_mask = 0;
		tmp = MAX_CLOCK_SEC_2STAGE * 1000000ULL * cycles_per_usec;
		dprintf("tmp=%llu, max_cycles_shift=%u\n", tmp, max_cycles_shift);
		while (tmp > 1) {
			tmp >>= 1;
			max_cycles_shift++;
			dprintf("tmp=%llu, max_cycles_shift=%u\n", tmp, max_cycles_shift);
		}
		// if use use (1ULL << max_cycles_shift) * 1000 / cycles_per_usec here we will
		// have a discontinuity every (1ULL << max_cycles_shift) cycles
		nsecs_for_max_cycles = (1ULL << max_cycles_shift) * *((unsigned long long *)mult) >> *shift;

		// Use a bitmask to calculate ticks % (1ULL << max_cycles_shift)
		for (tmp = 0; tmp < max_cycles_shift; tmp++)
			max_cycles_mask |= 1ULL << tmp;

		dprintf("max_cycles_shift=%u, 2^max_cycles_shift=%llu, nsecs_for_max_cycles=%llu, max_cycles_mask=%016llx\n",
				max_cycles_shift, (1ULL << max_cycles_shift),
				nsecs_for_max_cycles, max_cycles_mask);


		break;
		}
	case CLOCK64_LOCK: {
/*
 * This clock tick to nsec conversion also requires two stages.
 *
 * Stage 1: Add to nsec the current running total of elapsed long periods
 * Stage 2: Subtract from clock ticks the tick count corresponding to the
 *	most recently elapsed long period. Convert the remaining ticks to
 *	nsec and add to the previous nsec value.
 *
 * In practice the elapsed nsec from Stage 1 and the tick count subtracted
 * in Stage 2 will be maintained in a separate thread.
 *
 */
		calc_mult_shift(CLOCK64_2STAGE, mult, shift, MAX_CLOCK_SEC, cycles_per_usec);
		cycles_start = 0;
		break;
		}
	case CLOCK128_MULT_SHIFT: {
		__uint128_t max_mult, tmp;
		unsigned int sft = 0;

		/*
		 * Calculate the largest multiplier that will not
		 * produce a 128-bit overflow in the multiplication
		 * step of the clock ticks to nsec conversion
		 */
		max_mult = ((__uint128_t) ULLONG_MAX) << 64 | ULLONG_MAX;
		max_mult /= max_ticks;
		dprintf("max_ticks=%llu, __builtin_clzll=%d, max_mult=0x%016llx%016llx\n",
				max_ticks, __builtin_clzll(max_ticks),
				(unsigned long long) (max_mult >> 64),
				(unsigned long long) max_mult);

		/*
		 * Find the largest shift count that will produce
		 * a multiplier less than max_mult
		 */
		tmp = max_mult * cycles_per_usec / 1000;
		while (tmp > 1) {
			tmp >>= 1;
			sft++;
			dprintf("tmp=0x%016llx%016llx, sft=%u\n",
					(unsigned long long) (tmp >> 64),
					(unsigned long long) tmp, sft);
		}

		*shift = sft;
		*((__uint128_t *)mult) = (__uint128_t) (((__uint128_t)1 << sft) * 1000 / cycles_per_usec);
		break;
		}
	}
}

static int discontinuity(int mode, int delta_ticks, int delta_nsec,
			 unsigned long long start, unsigned long len)
{
	int i;
	unsigned long mismatches = 0, bad_mismatches = 0;
	unsigned long long delta, max_mismatch = 0;
	unsigned long long *ns = nsecs;

	for (i = 0; i < len; ns++, i++) {
		*ns = get_nsec(mode, start + i);
		if (i - delta_ticks >= 0) {
			if (*ns > *(ns - delta_ticks))
				delta = *ns - *(ns - delta_ticks);
			else
				delta = *(ns - delta_ticks) - *ns;
			if (delta > delta_nsec)
				delta -= delta_nsec;
			else
				delta = delta_nsec - delta;
			if (delta) {
				mismatches++;
				if (delta > 1)
					bad_mismatches++;
				if (delta > max_mismatch)
					max_mismatch = delta;
			}
		}
		if (!bad_mismatches)
			assert(max_mismatch == 0 || max_mismatch == 1);
		if (!mismatches)
			assert(max_mismatch == 0);
	}

	printf("%lu discontinuities (%lu%%) (%lu errors > 1ns, max delta = %lluns) for ticks = %llu...%llu\n",
		mismatches, (mismatches * 100) / len, bad_mismatches, max_mismatch, start,
		start + len - 1);
	return mismatches;
}

#define MIN_TICKS 1ULL
#define LEN 1000000000ULL
#define NSEC_ONE_SEC 1000000000ULL
#define TESTLEN 9

static long long test_clock(int mode, int cycles_per_usec, int fast_test,
			    int quiet, int delta_ticks, int delta_nsec)
{
	int i;
	long long delta;
	unsigned long long max_ticks;
	unsigned long long nsecs;
	void *mult;
	unsigned long long test_ns[TESTLEN] =
			{NSEC_ONE_SEC, NSEC_ONE_SEC,
			 NSEC_ONE_SEC, NSEC_ONE_SEC*60, NSEC_ONE_SEC*60*60,
			 NSEC_ONE_SEC*60*60*2, NSEC_ONE_SEC*60*60*4,
			 NSEC_ONE_SEC*60*60*8, NSEC_ONE_SEC*60*60*24};
	unsigned long long test_ticks[TESTLEN];

	max_ticks = MAX_CLOCK_SEC * (unsigned long long) cycles_per_usec * 1000000ULL;

	switch(mode) {
	case CLOCK64_MULT_SHIFT:
		mult = &clock_mult;
		break;
	case CLOCK64_EMULATE_128:
		mult = clock_mult64_128;
		break;
	case CLOCK64_2STAGE:
		mult = &clock_mult;
		break;
	case CLOCK64_LOCK:
		mult = &clock_mult;
		break;
	case CLOCK128_MULT_SHIFT:
		mult = &clock_mult128;
		break;
	default:
		assert(0);
	}
	calc_mult_shift(mode, mult, &clock_shift, MAX_CLOCK_SEC, cycles_per_usec);
	nsecs = get_nsec(mode, max_ticks);
	delta = nsecs/1000000 - MAX_CLOCK_SEC*1000;

	if (mode == CLOCK64_2STAGE) {
		test_ns[0] = nsecs_for_max_cycles - 1;
		test_ns[1] = nsecs_for_max_cycles;
		test_ticks[0] = (1ULL << max_cycles_shift) - 1;
		test_ticks[1] = (1ULL << max_cycles_shift);

		for (i = 2; i < TESTLEN; i++)
			test_ticks[i] = test_ns[i] / 1000 * cycles_per_usec;
	}
	else {
		for (i = 0; i < TESTLEN; i++)
			test_ticks[i] = test_ns[i] / 1000 * cycles_per_usec;
	}

	if (!quiet) {
		printf("cycles_per_usec=%d, delta_ticks=%d, delta_nsec=%d, max_ticks=%llu, shift=%u, 2^shift=%llu\n",
			cycles_per_usec, delta_ticks, delta_nsec, max_ticks, clock_shift, (1ULL << clock_shift));
		switch(mode) {
			case CLOCK64_LOCK:
			case CLOCK64_2STAGE:
			case CLOCK64_MULT_SHIFT: {
				printf("clock_mult=%llu, clock_mult / 2^clock_shift=%f\n",
					clock_mult, (double) clock_mult / (1ULL << clock_shift));
				break;
			}
			case CLOCK64_EMULATE_128: {
				printf("clock_mult=0x%016llx%016llx\n",
					clock_mult64_128[1], clock_mult64_128[0]);
				break;
			}
			case CLOCK128_MULT_SHIFT: {
				printf("clock_mult=0x%016llx%016llx\n",
					(unsigned long long) (clock_mult128 >> 64),
					(unsigned long long) clock_mult128);
				break;
			}
		}
		printf("get_nsec(max_ticks) = %lluns, should be %lluns, error<=abs(%lld)ms\n",
			nsecs, MAX_CLOCK_SEC*1000000000ULL, delta);
	}

	for (i = 0; i < TESTLEN; i++)
	{
		nsecs = get_nsec(mode, test_ticks[i]);
		delta = nsecs > test_ns[i] ? nsecs - test_ns[i] : test_ns[i] - nsecs;
		if (!quiet || delta > 0)
			printf("get_nsec(%llu)=%llu, expected %llu, delta=%llu\n",
				test_ticks[i], nsecs, test_ns[i], delta);
	}

	if (!fast_test) {
		discontinuity(mode, delta_ticks, delta_nsec, max_ticks - LEN + 1, LEN);
		discontinuity(mode, delta_ticks, delta_nsec, MIN_TICKS, LEN);
	}

	if (!quiet)
		printf("\n\n");

	return delta;
}

int main(int argc, char *argv[])
{
	nsecs = malloc(LEN * sizeof(unsigned long long));

	test_clock(CLOCK64_LOCK, 3333, 1, 0, 0, 0);
	test_clock(CLOCK64_LOCK, 1000, 1, 0, 1, 1);
	test_clock(CLOCK64_LOCK, 1100, 1, 0, 11, 10);
	test_clock(CLOCK64_LOCK, 3000, 1, 0, 3, 1);
	test_clock(CLOCK64_LOCK, 3333, 1, 0, 3333, 1000);
	test_clock(CLOCK64_LOCK, 3392, 1, 0, 424, 125);
	test_clock(CLOCK64_LOCK, 4500, 1, 0, 9, 2);
	test_clock(CLOCK64_LOCK, 5000, 1, 0, 5, 1);

	free(nsecs);
	return 0;
}
