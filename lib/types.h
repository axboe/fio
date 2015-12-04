#ifndef FIO_TYPES_H
#define FIO_TYPES_H

#ifndef CONFIG_HAVE_BOOL
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
