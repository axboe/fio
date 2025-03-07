#ifndef FIO_POW2_H
#define FIO_POW2_H

#include <inttypes.h>
#include "types.h"

static inline bool is_power_of_2(uint64_t val)
{
	return (val != 0 && ((val & (val - 1)) == 0));
}

#endif
