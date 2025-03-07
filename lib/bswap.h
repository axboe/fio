#ifndef FIO_BSWAP_H
#define FIO_BSWAP_H

#include <inttypes.h>

#ifdef CONFIG_LITTLE_ENDIAN
static inline uint32_t __be32_to_cpu(uint32_t val)
{
	uint32_t c1, c2, c3, c4;

	c1 = (val >> 24) & 0xff;
	c2 = (val >> 16) & 0xff;
	c3 = (val >> 8) & 0xff;
	c4 = val & 0xff;

	return c1 | c2 << 8 | c3 << 16 | c4 << 24;
}

static inline uint64_t __be64_to_cpu(uint64_t val)
{
	uint64_t c1, c2, c3, c4, c5, c6, c7, c8;

	c1 = (val >> 56) & 0xff;
	c2 = (val >> 48) & 0xff;
	c3 = (val >> 40) & 0xff;
	c4 = (val >> 32) & 0xff;
	c5 = (val >> 24) & 0xff;
	c6 = (val >> 16) & 0xff;
	c7 = (val >> 8) & 0xff;
	c8 = val & 0xff;

	return c1 | c2 << 8 | c3 << 16 | c4 << 24 | c5 << 32 | c6 << 40 | c7 << 48 | c8 << 56;
}
#else
static inline uint64_t __be64_to_cpu(uint64_t val)
{
	return val;
}

static inline uint32_t __be32_to_cpu(uint32_t val)
{
	return val;
}
#endif

#endif
