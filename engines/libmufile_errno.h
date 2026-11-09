#ifndef FIO_LIBMUFILE_ERRNO_H
#define FIO_LIBMUFILE_ERRNO_H

#include <sys/types.h>

/*
 * gpuaccel treats exactly -1 as errno. muFileRead/muFileWrite return
 * -MUfileOpError, and MU_FILE_DRIVER_NOT_INITIALIZED is 1, so a raw
 * -1 is a library error. Shift that one value out of the sentinel.
 */
#define LIBMUFILE_ERR_ALIAS 1000

static inline ssize_t libmufile_translate_return(ssize_t n)
{
	if (n >= 0)
		return n;
	if (n == -1)
		return -(ssize_t)(1 + LIBMUFILE_ERR_ALIAS);
	return n;
}

static inline int libmufile_translate_error_code(int error_code)
{
	if (error_code == 1 + LIBMUFILE_ERR_ALIAS)
		return 1;
	return error_code;
}

#endif
