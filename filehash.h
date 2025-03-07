#ifndef FIO_FILE_HASH_H
#define FIO_FILE_HASH_H

#include "lib/types.h"

extern void file_hash_init(void);
extern void file_hash_exit(void);
extern struct fio_file *lookup_file_hash(const char *);
extern struct fio_file *add_file_hash(struct fio_file *);
extern void remove_file_hash(struct fio_file *);
extern void fio_file_hash_lock(void);
extern void fio_file_hash_unlock(void);
extern bool file_bloom_exists(const char *, bool);

#endif
