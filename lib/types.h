#ifndef FIO_TYPES_H
#define FIO_TYPES_H

#if !defined(CONFIG_HAVE_BOOL) && !defined(__cplusplus)
typedef int bool;
#ifndef false
#define false	0
#endif
#ifndef true
#define true	1
#endif
#else
#include <stdbool.h>
#endif

#endif
