#include "hweight.h"

unsigned int hweight8(uint8_t w)
{
	unsigned int res = w - ((w >> 1) & 0x55);

	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res + (res >> 4)) & 0x0F;
}

unsigned int hweight32(uint32_t w)
{
	unsigned int res = w - ((w >> 1) & 0x55555555);

	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
}

unsigned int hweight64(uint64_t w)
{
#if BITS_PER_LONG == 32
	return hweight32((unsigned int)(w >> 32)) + hweight32((unsigned int)w);
#else
	uint64_t res = w - ((w >> 1) & 0x5555555555555555ULL);
	res = (res & 0x3333333333333333ULL) + ((res >> 2) & 0x3333333333333333ULL);
	res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
	res = res + (res >> 8);
	res = res + (res >> 16);
	return (res + (res >> 32)) & 0x00000000000000FFULL;
#endif
}
