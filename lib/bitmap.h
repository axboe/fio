#ifndef FIO_BITMAP_H
#define FIO_BITMAP_H

#include <inttypes.h>

struct bitmap;
struct bitmap *bitmap_new(unsigned long nr_bits);
void bitmap_free(struct bitmap *bm);

void bitmap_clear(struct bitmap *bitmap, uint64_t bit_nr);
void bitmap_set(struct bitmap *bitmap, uint64_t bit_nr);
unsigned int bitmap_set_nr(struct bitmap *bitmap, uint64_t bit_nr, unsigned int nr_bits);
int bitmap_isset(struct bitmap *bitmap, uint64_t bit_nr);
uint64_t bitmap_first_free(struct bitmap *bitmap);
uint64_t bitmap_next_free(struct bitmap *bitmap, uint64_t bit_nr);
void bitmap_reset(struct bitmap *bitmap);

#endif
