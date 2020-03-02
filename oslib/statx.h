#ifndef CONFIG_HAVE_STATX
#ifdef CONFIG_HAVE_STATX_SYSCALL
#include <linux/stat.h>
#include <sys/stat.h>
#else
#define STATX_ALL 0
#undef statx
struct statx
{
};
#endif
int statx(int dfd, const char *pathname, int flags, unsigned int mask,
	  struct statx *buffer);
#endif
