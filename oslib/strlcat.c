#include <string.h>

size_t strlcat(char *dst, const char *src, size_t size)
{
	size_t dstlen;
	size_t srclen;

	dstlen = strlen(dst);
	size -= dstlen + 1;

	/* return if no room */
	if (!size)
		return dstlen;

	srclen = strlen(src);
	if (srclen > size)
		srclen = size;

	memcpy(dst + dstlen, src, srclen);
	dst[dstlen + srclen] = '\0';

	return dstlen + srclen;
}
