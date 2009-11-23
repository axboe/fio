#include <malloc.h>
#include <stdlib.h>

#include "compiler/compiler.h"

int __weak posix_memalign(void **ptr, size_t align, size_t size)
{
	*ptr = memalign(align, size);
	if (*ptr)
		return 0;

	return ENOMEM;
}

int __weak posix_fallocate(int fd, off_t offset, off_t len)
{
	return 0;
}
