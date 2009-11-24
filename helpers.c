#include <malloc.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

int __weak inet_aton(const char *cp, struct in_addr *inp)
{
	return 0;
}
