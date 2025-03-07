#ifndef FIO_STRNTOL_H
#define FIO_STRNTOL_H

#include <stdint.h>

long strntol(const char *str, size_t sz, char **end, int base);

#endif
