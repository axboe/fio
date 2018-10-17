#ifndef FIO_MEMALIGN_H
#define FIO_MEMALIGN_H

#include <inttypes.h>
#include <stdbool.h>

extern void *fio_memalign(size_t alignment, size_t size, bool shared);
extern void fio_memfree(void *ptr, size_t size, bool shared);

#endif
