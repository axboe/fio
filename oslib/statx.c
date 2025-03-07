#ifndef CONFIG_HAVE_STATX
#include "statx.h"

#ifdef CONFIG_HAVE_STATX_SYSCALL
#include <unistd.h>
#include <sys/syscall.h>

int statx(int dfd, const char *pathname, int flags, unsigned int mask,
	  struct statx *buffer)
{
	return syscall(__NR_statx, dfd, pathname, flags, mask, buffer);
}
#else
#include <errno.h>

int statx(int dfd, const char *pathname, int flags, unsigned int mask,
	  struct statx *buffer)
{
	errno = EINVAL;
	return -1;
}
#endif
#endif
