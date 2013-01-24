#ifndef FIO_GETRUSAGE_H
#define FIO_GETRUSAGE_H

#include <sys/time.h>
#include <sys/resource.h>

extern int fio_getrusage(struct rusage *ru);

#endif
