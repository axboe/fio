#ifdef CONFIG_STRCASESTR

#include <string.h>

#else

#ifndef FIO_STRCASESTR_H
#define FIO_STRCASESTR_H

char *strcasestr(const char *haystack, const char *needle);

#endif
#endif
