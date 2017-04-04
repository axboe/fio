#ifndef FIO_NUM2STR_H
#define FIO_NUM2STR_H

#include <inttypes.h>

#define N2S_NONE	0
#define N2S_BITPERSEC	1	/* match unit_base for bit rates */
#define N2S_PERSEC	2
#define N2S_BIT		3
#define N2S_BYTE	4
#define N2S_BYTEPERSEC	8	/* match unit_base for byte rates */

extern char *num2str(uint64_t, int, int, int, int);

#endif
