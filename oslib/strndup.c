#ifndef CONFIG_HAVE_STRNDUP

#include <stdlib.h>
#include <string.h>
#include "strndup.h"

char *strndup(const char *s, size_t n)
{
	char *str = malloc(n + 1);

	if (str) {
		strncpy(str, s, n);
		str[n] = '\0';
	}

	return str;
}

#endif
