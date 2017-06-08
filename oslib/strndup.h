#ifdef CONFIG_HAVE_STRNDUP

#include <string.h>

#else

char *strndup(const char *s, size_t n);

#endif
