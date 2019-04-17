#include <stdio.h>

#include "lfsr.h"
#include "../compiler/compiler.h"

/*
 * LFSR taps retrieved from:
 * http://home1.gte.net/res0658s/electronics/LFSRtaps.html
 *
 * The memory overhead of the following tap table should be relatively small,
 * no more than 400 bytes.
 */
static uint8_t lfsr_taps[64][FIO_MAX_TAPS] =
{
	{0}, {0}, {0},		//LFSRs with less that 3-bits cannot exist
	{3, 2},			//Tap position for 3-bit LFSR
	{4, 3},			//Tap position for 4-bit LFSR
	{5, 3},			//Tap position for 5-bit LFSR
	{6, 5},			//Tap position for 6-bit LFSR
	{7, 6},			//Tap position for 7-bit LFSR
	{8, 6, 5 ,4},		//Tap position for 8-bit LFSR
	{9, 5},			//Tap position for 9-bit LFSR
	{10, 7},		//Tap position for 10-bit LFSR
	{11, 9},		//Tap position for 11-bit LFSR
	{12, 6, 4, 1},		//Tap position for 12-bit LFSR
	{13, 4, 3, 1},		//Tap position for 13-bit LFSR
	{14, 5, 3, 1},		//Tap position for 14-bit LFSR
	{15, 14},		//Tap position for 15-bit LFSR
	{16, 15, 13, 4},	//Tap position for 16-bit LFSR
	{17, 14},		//Tap position for 17-bit LFSR
	{18, 11},		//Tap position for 18-bit LFSR
	{19, 6, 2, 1},		//Tap position for 19-bit LFSR
	{20, 17},		//Tap position for 20-bit LFSR
	{21, 19},		//Tap position for 21-bit LFSR
	{22, 21},		//Tap position for 22-bit LFSR
	{23, 18},		//Tap position for 23-bit LFSR
	{24, 23, 22, 17},	//Tap position for 24-bit LFSR
	{25, 22},		//Tap position for 25-bit LFSR
	{26, 6, 2, 1},		//Tap position for 26-bit LFSR
	{27, 5, 2, 1},		//Tap position for 27-bit LFSR
	{28, 25},		//Tap position for 28-bit LFSR
	{29, 27},		//Tap position for 29-bit LFSR
	{30, 6, 4, 1},		//Tap position for 30-bit LFSR
	{31, 28},		//Tap position for 31-bit LFSR
	{32, 31, 29, 1},	//Tap position for 32-bit LFSR
	{33, 20},		//Tap position for 33-bit LFSR
	{34, 27, 2, 1},		//Tap position for 34-bit LFSR
	{35, 33},		//Tap position for 35-bit LFSR
	{36, 25},		//Tap position for 36-bit LFSR
	{37, 5, 4, 3, 2, 1},	//Tap position for 37-bit LFSR
	{38, 6, 5, 1},		//Tap position for 38-bit LFSR
	{39, 35},		//Tap position for 39-bit LFSR
	{40, 38, 21, 19},	//Tap position for 40-bit LFSR
	{41, 38},		//Tap position for 41-bit LFSR
	{42, 41, 20, 19},	//Tap position for 42-bit LFSR
	{43, 42, 38, 37},	//Tap position for 43-bit LFSR
	{44, 43, 18, 17},	//Tap position for 44-bit LFSR
	{45, 44, 42, 41},	//Tap position for 45-bit LFSR
	{46, 45, 26, 25},	//Tap position for 46-bit LFSR
	{47, 42},		//Tap position for 47-bit LFSR
	{48, 47, 21, 20},	//Tap position for 48-bit LFSR
	{49, 40},		//Tap position for 49-bit LFSR
	{50, 49, 24, 23},	//Tap position for 50-bit LFSR
	{51, 50, 36, 35},	//Tap position for 51-bit LFSR
	{52, 49},		//Tap position for 52-bit LFSR
	{53, 52, 38, 37},	//Tap position for 53-bit LFSR
	{54, 53, 18, 17},	//Tap position for 54-bit LFSR
	{55, 31},		//Tap position for 55-bit LFSR
	{56, 55, 35, 34},	//Tap position for 56-bit LFSR
	{57, 50},		//Tap position for 57-bit LFSR
	{58, 39},		//Tap position for 58-bit LFSR
	{59, 58, 38, 37},	//Tap position for 59-bit LFSR
	{60, 59},		//Tap position for 60-bit LFSR
	{61, 60, 46, 45},	//Tap position for 61-bit LFSR
	{62, 61, 6, 5},		//Tap position for 62-bit LFSR
	{63, 62},		//Tap position for 63-bit LFSR
};

#define __LFSR_NEXT(__fl, __v)						\
	__v = ((__v >> 1) | __fl->cached_bit) ^			\
			(((__v & 1ULL) - 1ULL) & __fl->xormask);

static inline void __lfsr_next(struct fio_lfsr *fl, unsigned int spin)
{
	/*
	 * This should be O(1) since most compilers will create a jump table for
	 * this switch.
	 */
	switch (spin) {
		case 15: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case 14: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case 13: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case 12: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case 11: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case 10: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  9: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  8: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  7: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  6: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  5: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  4: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  3: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  2: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  1: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		case  0: __LFSR_NEXT(fl, fl->last_val);
		/* fall through */
		default: break;
	}
}

/*
 * lfsr_next does the following:
 *
 * a. Return if the number of max values has been exceeded.
 * b. Check if we have a spin value that produces a repeating subsequence.
 *    This is previously calculated in `prepare_spin` and cycle_length should
 *    be > 0. If we do have such a spin:
 *
 *    i. Decrement the calculated cycle.
 *    ii. If it reaches zero, add "+1" to the spin and reset the cycle_length
 *        (we have it cached in the struct fio_lfsr)
 *
 *    In either case, continue with the calculation of the next value.
 * c. Check if the calculated value exceeds the desirable range. In this case,
 *    go back to b, else return.
 */
int lfsr_next(struct fio_lfsr *fl, uint64_t *off)
{
	if (fl->num_vals++ > fl->max_val)
		return 1;

	do {
		if (fl->cycle_length && !--fl->cycle_length) {
			__lfsr_next(fl, fl->spin + 1);
			fl->cycle_length = fl->cached_cycle_length;
		} else
			__lfsr_next(fl, fl->spin);
	} while (fio_unlikely(fl->last_val > fl->max_val));

	*off = fl->last_val;
	return 0;
}

static uint64_t lfsr_create_xormask(uint8_t *taps)
{
	int i;
	uint64_t xormask = 0;

	for(i = 0; i < FIO_MAX_TAPS && taps[i] != 0; i++)
		xormask |= 1ULL << (taps[i] - 1);

	return xormask;
}

static uint8_t *find_lfsr(uint64_t size)
{
	int i;

	/*
	 * For an LFSR, there is always a prohibited state (all ones).
	 * Thus, if we need to find the proper LFSR for our size, we must
	 * take that into account.
	 */
	for (i = 3; i < 64; i++)
		if ((1ULL << i) > size)
			return lfsr_taps[i];

	return NULL;
}

/*
 * It is well-known that all maximal n-bit LFSRs will start repeating
 * themselves after their 2^n iteration. The introduction of spins however, is
 * possible to create a repetition of a sub-sequence before we hit that mark.
 * This happens if:
 *
 * [1]: ((2^n - 1) * i) % (spin + 1) == 0,
 * where "n" is LFSR's bits and "i" any number within the range [1,spin]
 *
 * It is important to know beforehand if a spin can cause a repetition of a
 * sub-sequence (cycle) and its length. However, calculating (2^n - 1) * i may
 * produce a buffer overflow for "n" close to 64, so we expand the above to:
 *
 * [2]: (2^n - 1) -> (x * (spin + 1) + y), where x >= 0 and 0 <= y <= spin
 *
 * Thus, [1] is equivalent to (y * i) % (spin + 1) == 0;
 * Also, the cycle's length will be (x * i) + (y * i) / (spin + 1)
 */
static int prepare_spin(struct fio_lfsr *fl, unsigned int spin)
{
	uint64_t max = (fl->cached_bit << 1) - 1;
	uint64_t x, y;
	int i;

	if (spin > 15)
		return 1;

	x = max / (spin + 1);
	y = max % (spin + 1);
	fl->cycle_length = 0;	/* No cycle occurs, other than the expected */
	fl->spin = spin;

	for (i = 1; i <= spin; i++) {
		if ((y * i) % (spin + 1) == 0) {
			fl->cycle_length = (x * i) + (y * i) / (spin + 1);
			break;
		}
	}
	fl->cached_cycle_length = fl->cycle_length;

	/*
	 * Increment cycle length for the first time only since the stored value
	 * will not be printed otherwise.
	 */
	fl->cycle_length++;

	return 0;
}

int lfsr_reset(struct fio_lfsr *fl, uint64_t seed)
{
	uint64_t bitmask = (fl->cached_bit << 1) - 1;

	fl->num_vals = 0;
	fl->last_val = seed & bitmask;

	/* All-ones state is illegal for XNOR LFSRs */
	if (fl->last_val == bitmask)
		return 1;

	return 0;
}

int lfsr_init(struct fio_lfsr *fl, uint64_t nums, uint64_t seed,
	      unsigned int spin)
{
	uint8_t *taps;

	taps = find_lfsr(nums);
	if (!taps)
		return 1;

	fl->max_val = nums - 1;
	fl->xormask = lfsr_create_xormask(taps);
	fl->cached_bit = 1ULL << (taps[0] - 1);

	if (prepare_spin(fl, spin))
		return 1;

	if (lfsr_reset(fl, seed))
		return 1;

	return 0;
}
