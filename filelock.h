#ifndef FIO_LOCK_FILE_H
#define FIO_LOCK_FILE_H

#include "lib/types.h"

extern void fio_lock_file(const char *);
extern bool fio_trylock_file(const char *);
extern void fio_unlock_file(const char *);

extern int fio_filelock_init(void);
extern void fio_filelock_exit(void);

#endif
