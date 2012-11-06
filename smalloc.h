#ifndef FIO_SMALLOC_H
#define FIO_SMALLOC_H

extern void *smalloc(size_t);
extern void sfree(void *);
extern char *smalloc_strdup(const char *);
extern void sinit(void);
extern void scleanup(void);

extern unsigned int smalloc_pool_size;

#endif
