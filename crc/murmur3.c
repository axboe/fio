#include "murmur3.h"

static inline uint32_t rotl32(uint32_t x, int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

//-----------------------------------------------------------------------------
// Finalization mix - force all bits of a hash block to avalanche

static inline uint32_t fmix32(uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;

	return h;
}

static uint32_t murmur3_tail(const uint8_t *data, const int nblocks,
			     uint32_t len, const uint32_t c1,
			     const uint32_t c2, uint32_t h1)
{
	const uint8_t *tail = (const uint8_t *)(data + nblocks * 4);

	uint32_t k1 = 0;
	switch (len & 3) {
	case 3:
		k1 ^= tail[2] << 16;
	case 2:
		k1 ^= tail[1] << 8;
	case 1:
		k1 ^= tail[0];
		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;
		h1 ^= k1;
	};

	return fmix32(h1 ^ len);
}

uint32_t murmurhash3(const void *key, uint32_t len, uint32_t seed)
{
	const uint8_t *data = (const uint8_t *)key;
	const int nblocks = len / 4;
	uint32_t h1 = seed;
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	const uint32_t *blocks = (const uint32_t *)(data + nblocks * 4);
	int i;

	for (i = -nblocks; i; i++) {
		uint32_t k1 = blocks[i];

		k1 *= c1;
		k1 = rotl32(k1, 15);
		k1 *= c2;

		h1 ^= k1;
		h1 = rotl32(h1, 13);
		h1 = h1 * 5 + 0xe6546b64;
	}

	return murmur3_tail(data, nblocks, len, c1, c2, h1);
}
