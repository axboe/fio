#ifndef FIO_BLOOM_H
#define FIO_BLOOM_H

#include <inttypes.h>
#include "../lib/types.h"

struct bloom;

struct bloom *bloom_new(uint64_t entries);
void bloom_free(struct bloom *b);
bool bloom_set(struct bloom *b, uint32_t *data, unsigned int nwords);
bool bloom_string(struct bloom *b, const char *data, unsigned int len, bool);

#endif
