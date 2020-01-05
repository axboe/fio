#include <stdlib.h>
#include "../unittest.h"

#include "../../lib/memalign.h"

static void test_memalign_1(void)
{
	size_t align = 4096;
	void *p = __fio_memalign(align, 1234, malloc);

	if (p)
		CU_ASSERT_EQUAL(((int)(uintptr_t)p) & (align - 1), 0);
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "memalign/1",
		.fn	= test_memalign_1,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_lib_memalign(void)
{
	return fio_unittest_add_suite("lib/memalign.c", NULL, NULL, tests);
}
