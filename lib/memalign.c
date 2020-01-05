#include <assert.h>
#include <stdlib.h>

#include "memalign.h"
#include "smalloc.h"

#define PTR_ALIGN(ptr, mask)   \
	(char *)((uintptr_t)((ptr) + (mask)) & ~(mask))

struct align_footer {
	unsigned int offset;
};

void *__fio_memalign(size_t alignment, size_t size, malloc_fn fn)
{
	struct align_footer *f;
	void *ptr, *ret = NULL;

	assert(!(alignment & (alignment - 1)));

	ptr = fn(size + alignment + sizeof(*f) - 1);
	if (ptr) {
		ret = PTR_ALIGN(ptr, alignment - 1);
		f = ret + size;
		f->offset = (uintptr_t) ret - (uintptr_t) ptr;
	}

	return ret;
}

void __fio_memfree(void *ptr, size_t size, free_fn fn)
{
	struct align_footer *f = ptr + size;

	fn(ptr - f->offset);
}
