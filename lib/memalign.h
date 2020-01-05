#ifndef FIO_MEMALIGN_H
#define FIO_MEMALIGN_H

#include <inttypes.h>
#include <stdbool.h>

typedef void* (*malloc_fn)(size_t);
typedef void (*free_fn)(void*);

extern void *__fio_memalign(size_t alignment, size_t size, malloc_fn fn);
extern void __fio_memfree(void *ptr, size_t size, free_fn fn);

#endif
