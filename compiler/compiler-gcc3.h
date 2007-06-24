#ifndef FIO_COMPILER_GCC3_H
#define FIO_COMPILER_GCC3_H

#if __GNUC_MINOR__ >= 4
#ifndef __must_check
#define __must_check		__attribute__((warn_unused_result))
#endif
#endif

#endif
