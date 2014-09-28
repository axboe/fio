#include "fnv.h"

#define FNV_PRIME	0x100000001b3ULL

uint64_t fnv(const void *buf, uint32_t len, uint64_t hval)
{
	const uint64_t *ptr = buf;
	const uint64_t *end = (void *) buf + len;

	while (ptr < end) {
		hval *= FNV_PRIME;
		hval ^= (uint64_t) *ptr++;
	}

	return hval;
}
