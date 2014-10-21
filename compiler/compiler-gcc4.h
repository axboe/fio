#ifndef FIO_COMPILER_GCC4_H
#define FIO_COMPILER_GCC4_H

#ifndef __must_check
#define __must_check		__attribute__((warn_unused_result))
#endif

#define GCC_VERSION (__GNUC__ * 10000		\
			+ __GNUC_MINOR__ * 100	\
			+ __GNUC_PATCHLEVEL__)

#if GCC_VERSION >= 40300
#define __compiletime_warning(message)	__attribute__((warning(message)))
#define __compiletime_error(message)	__attribute__((error(message)))
#endif

#endif
