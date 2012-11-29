#ifndef FIO_BITMAP_H
#define FIO_BITMAP_H

#include <inttypes.h>

struct axmap;
struct axmap *axmap_new(unsigned long nr_bits);
void axmap_free(struct axmap *bm);

void axmap_clear(struct axmap *axmap, uint64_t bit_nr);
void axmap_set(struct axmap *axmap, uint64_t bit_nr);
unsigned int axmap_set_nr(struct axmap *axmap, uint64_t bit_nr, unsigned int nr_bits);
int axmap_isset(struct axmap *axmap, uint64_t bit_nr);
uint64_t axmap_first_free(struct axmap *axmap);
uint64_t axmap_next_free(struct axmap *axmap, uint64_t bit_nr);
void axmap_reset(struct axmap *axmap);

#endif
