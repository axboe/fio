#ifndef FIO_NUM2STR_H
#define FIO_NUM2STR_H

#include <inttypes.h>

enum n2s_unit {
	N2S_NONE	= 0,
	N2S_PERSEC	= 1,
	N2S_BYTE	= 2,
	N2S_BIT		= 3,
	N2S_BYTEPERSEC	= 4,
	N2S_BITPERSEC	= 5,
};

extern char *num2str(uint64_t, int, int, int, enum n2s_unit);

#endif
