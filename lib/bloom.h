#ifndef FIO_BLOOM_H
#define FIO_BLOOM_H

#include <inttypes.h>

struct bloom;

struct bloom *bloom_new(uint64_t entries);
void bloom_free(struct bloom *b);
int bloom_set(struct bloom *b, uint32_t *data, unsigned int nwords);

#endif
