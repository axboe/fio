#ifndef _LINUX_HASH_H
#define _LINUX_HASH_H

#include <inttypes.h>
#include "arch/arch.h"

/* Fast hashing routine for a long.
   (C) 2002 William Lee Irwin III, IBM */

/*
 * Knuth recommends primes in approximately golden ratio to the maximum
 * integer representable by a machine word for multiplicative hashing.
 * Chuck Lever verified the effectiveness of this technique:
 * http://www.citi.umich.edu/techreports/reports/citi-tr-00-1.pdf
 *
 * These primes are chosen to be bit-sparse, that is operations on
 * them can use shifts and additions instead of multiplications for
 * machines where multiplications are slow.
 */

#if BITS_PER_LONG == 32
/* 2^31 + 2^29 - 2^25 + 2^22 - 2^19 - 2^16 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e370001UL
#elif BITS_PER_LONG == 64
/*  2^63 + 2^61 - 2^57 + 2^54 - 2^51 - 2^18 + 1 */
#define GOLDEN_RATIO_PRIME 0x9e37fffffffc0001UL
#else
#error Define GOLDEN_RATIO_PRIME for your wordsize.
#endif

#define GR_PRIME_64	0x9e37fffffffc0001ULL

static inline unsigned long __hash_long(unsigned long val)
{
	unsigned long hash = val;

#if BITS_PER_LONG == 64
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#else
	/* On some cpus multiply is faster, on others gcc will do shifts */
	hash *= GOLDEN_RATIO_PRIME;
#endif

	return hash;
}

static inline unsigned long hash_long(unsigned long val, unsigned int bits)
{
	/* High bits are more random, so use them. */
	return __hash_long(val) >> (BITS_PER_LONG - bits);
}

static inline uint64_t __hash_u64(uint64_t val)
{
	return val * GR_PRIME_64;
}
	
static inline unsigned long hash_ptr(void *ptr, unsigned int bits)
{
	return hash_long((uintptr_t)ptr, bits);
}

/*
 * Bob Jenkins jhash
 */

#define JHASH_INITVAL	GOLDEN_RATIO_PRIME

static inline uint32_t rol32(uint32_t word, uint32_t shift)
{
	return (word << shift) | (word >> (32 - shift));
}

/* __jhash_mix -- mix 3 32-bit values reversibly. */
#define __jhash_mix(a, b, c)			\
{						\
	a -= c;  a ^= rol32(c, 4);  c += b;	\
	b -= a;  b ^= rol32(a, 6);  a += c;	\
	c -= b;  c ^= rol32(b, 8);  b += a;	\
	a -= c;  a ^= rol32(c, 16); c += b;	\
	b -= a;  b ^= rol32(a, 19); a += c;	\
	c -= b;  c ^= rol32(b, 4);  b += a;	\
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c */
#define __jhash_final(a, b, c)			\
{						\
	c ^= b; c -= rol32(b, 14);		\
	a ^= c; a -= rol32(c, 11);		\
	b ^= a; b -= rol32(a, 25);		\
	c ^= b; c -= rol32(b, 16);		\
	a ^= c; a -= rol32(c, 4);		\
	b ^= a; b -= rol32(a, 14);		\
	c ^= b; c -= rol32(b, 24);		\
}

static inline uint32_t jhash(const void *key, uint32_t length, uint32_t initval)
{
	const uint8_t *k = key;
	uint32_t a, b, c;

	/* Set up the internal state */
	a = b = c = JHASH_INITVAL + length + initval;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += *k;
		b += *(k + 4);
		c += *(k + 8);
		__jhash_mix(a, b, c);
		length -= 12;
		k += 12;
	}

	/* Last block: affect all 32 bits of (c) */
	/* All the case statements fall through */
	switch (length) {
	case 12: c += (uint32_t) k[11] << 24;
	case 11: c += (uint32_t) k[10] << 16;
	case 10: c += (uint32_t) k[9] << 8;
	case 9:  c += k[8];
	case 8:  b += (uint32_t) k[7] << 24;
	case 7:  b += (uint32_t) k[6] << 16;
	case 6:  b += (uint32_t) k[5] << 8;
	case 5:  b += k[4];
	case 4:  a += (uint32_t) k[3] << 24;
	case 3:  a += (uint32_t) k[2] << 16;
	case 2:  a += (uint32_t) k[1] << 8;
	case 1:  a += k[0];
		 __jhash_final(a, b, c);
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

#endif /* _LINUX_HASH_H */
