#ifndef FIO_MEMALIGN_H
#define FIO_MEMALIGN_H

extern void *fio_memalign(size_t alignment, size_t size);
extern void fio_memfree(void *ptr, size_t size);

#endif
