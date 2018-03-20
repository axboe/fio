#ifndef CONFIG_STRCASESTR

#include <ctype.h>
#include <stddef.h>
#include "strcasestr.h"

char *strcasestr(const char *s1, const char *s2)
{
	const char *s = s1;
	const char *p = s2;

	do {
		if (!*p)
			return (char *) s1;
		if ((*p == *s) ||
		    (tolower(*p) == tolower(*s))) {
			++p;
			++s;
		} else {
			p = s2;
			if (!*s)
				return NULL;
			s = ++s1;
		}
	} while (1);

	return *p ? NULL : (char *) s1;
}

#endif
