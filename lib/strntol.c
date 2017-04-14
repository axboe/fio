#include <string.h>
#include <stdlib.h>
#include <limits.h>

#include "strntol.h"

long strntol(const char *str, size_t sz, char **end, int base)
{
	/* Expect that digit representation of LONG_MAX/MIN
	 * not greater than this buffer */
	char buf[24];
	long ret;
	const char *beg = str;

	/* Catch up leading spaces */
	for (; beg && sz && *beg == ' '; beg++, sz--)
		;

	if (!sz || sz >= sizeof(buf)) {
		if (end)
			*end = (char *)str;
		return 0;
	}

	memcpy(buf, beg, sz);
	buf[sz] = '\0';
	ret = strtol(buf, end, base);
	if (ret == LONG_MIN || ret == LONG_MAX)
		return ret;
	if (end)
		*end = (char *)str + (*end - buf);
	return ret;
}
