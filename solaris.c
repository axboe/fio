#include <stdlib.h>
#include <errno.h>
#include "compiler/compiler.h"

/*
 * Some Solaris versions don't have posix_memalign(), provide a private
 * weak alternative
 */
int __weak posix_memalign(void **ptr, size_t align, size_t size)
{
	*ptr = memalign(align, size);
	if (*ptr)
		return 0;

	return ENOMEM;
}
