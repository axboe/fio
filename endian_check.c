#include <stdint.h>
#include "os/os.h"

int endian_check(void)
{
	union {
		uint8_t c[8];
		uint64_t v;
	} u;
	int le = 0, be = 0;

	u.v = 0x12;
	if (u.c[7] == 0x12)
		be = 1;
	else if (u.c[0] == 0x12)
		le = 1;

#if defined(FIO_LITTLE_ENDIAN)
	if (be)
		return 1;
#elif defined(FIO_BIG_ENDIAN)
	if (le)
		return 1;
#else
	return 1;
#endif

	if (!le && !be)
		return 1;

	return 0;
}

