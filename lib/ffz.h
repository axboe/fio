#ifndef FIO_FFZ_H
#define FIO_FFZ_H

static inline int __ffs(unsigned long word)
{
	int r = 0;

#if BITS_PER_LONG == 64
	if ((word & 0xffffffff) == 0) {
		r += 32;
		word >>= 32;
	}
#endif
	if (!(word & 0xffff)) {
		word >>= 16;
		r += 16;
	}
	if (!(word & 0xff)) {
		word >>= 8;
		r += 8;
	}
	if (!(word & 0xf)) {
		word >>= 4;
		r += 4;
	}
	if (!(word & 3)) {
		word >>= 2;
		r += 2;
	}
	if (!(word & 1)) {
		word >>= 1;
		r += 1;
	}

	return r;
}

static inline int ffz(unsigned long bitmask)
{
	return __ffs(~bitmask);
}

#endif
