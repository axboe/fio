#ifndef LINUX_DEV_LOOKUP
#define LINUX_DEV_LOOKUP

int blktrace_lookup_device(const char *redirect, char *path, unsigned int maj,
			   unsigned int min);

#endif
