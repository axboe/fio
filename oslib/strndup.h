#ifndef CONFIG_HAVE_STRNDUP

#ifndef FIO_STRNDUP_LIB_H
#define FIO_STRNDUP_LIB_H

#include <stddef.h>

char *strndup(const char *s, size_t n);

#endif

#endif
