#ifndef FIO_MURMUR3_H
#define FIO_MURMUR3_H

#include <inttypes.h>

uint32_t murmurhash3(const void *key, uint32_t len, uint32_t seed);

#endif
