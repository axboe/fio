#ifndef FIO_ROUNDUP_H
#define FIO_ROUNDUP_H

#include "lib/fls.h"

static inline unsigned roundup_pow2(unsigned depth)
{
	return 1UL << __fls(depth - 1);
}

#endif
