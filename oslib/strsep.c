#ifndef CONFIG_STRSEP

#include <stddef.h>
#include "strsep.h"

char *strsep(char **stringp, const char *delim)
{
	char *s, *tok;
	const char *spanp;
	int c, sc;

	s = *stringp;
	if (!s)
		return NULL;

	tok = s;
	do {
		c = *s++;
		spanp = delim;
		do {
			sc = *spanp++;
			if (sc == c) {
				if (c == 0)
					s = NULL;
				else
					s[-1] = 0;
				*stringp = s;
				return tok;
			}
		} while (sc != 0);
	} while (1);
}

#endif
