#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

#include "memalign.h"

struct align_footer {
	unsigned int offset;
};

#define PTR_ALIGN(ptr, mask)	\
	(char *) (((uintptr_t) ((ptr) + (mask)) & ~(mask)))

void *fio_memalign(size_t alignment, size_t size)
{
	struct align_footer *f;
	void *ptr, *ret = NULL;

	assert(!(alignment & (alignment - 1)));

	ptr = malloc(size + alignment + size + sizeof(*f) - 1);
	if (ptr) {
		ret = PTR_ALIGN(ptr, alignment);
		f = ret + size;
		f->offset = (uintptr_t) ret - (uintptr_t) ptr;
	}

	return ret;
}

void fio_memfree(void *ptr, size_t size)
{
	struct align_footer *f = ptr + size;

	free(ptr - f->offset);
}
