#ifndef FIO_FFZ_H
#define FIO_FFZ_H

static inline int __ffs(int word)
{
	int r = 0;

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

static inline int ffz(unsigned int bitmask)
{
	return ffs(~bitmask);
}

#endif
