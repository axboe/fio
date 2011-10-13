#ifndef FIO_IEEE754_H
#define FIO_IEEE754_H

#include <inttypes.h>

extern uint64_t pack754(long double f, unsigned bits, unsigned expbits);
extern long double unpack754(uint64_t i, unsigned bits, unsigned expbits);

#define fio_double_to_uint64(val)	pack754((val), 64, 11)
#define fio_uint64_to_double(val)	unpack754((val), 64, 11)

typedef struct fio_fp64 {
	union {
		uint64_t i;
		double f;
		uint8_t filler[16];
	} u;
} fio_fp64_t;

#endif
