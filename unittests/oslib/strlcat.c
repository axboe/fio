#include "../unittest.h"

#ifndef CONFIG_STRLCAT
#include "../../oslib/strlcat.h"
#else
#include <string.h>
#endif

static void test_strlcat_1(void)
{
	char dst[32];
	char src[] = "test";
	size_t ret;

	dst[0] = '\0';
	ret = strlcat(dst, src, sizeof(dst));

	CU_ASSERT_EQUAL(strcmp(dst, "test"), 0);
	CU_ASSERT_EQUAL(ret, 4); /* total length it tried to create */
}

static void test_strlcat_2(void)
{
	char dst[32];
	char src[] = "test";
	size_t ret;

	dst[0] = '\0';
	ret = strlcat(dst, src, strlen(dst));

	CU_ASSERT_EQUAL(strcmp(dst, ""), 0);
	CU_ASSERT_EQUAL(ret, 4); /* total length it tried to create */
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "strlcat/1",
		.fn	= test_strlcat_1,
	},
	{
		.name	= "strlcat/2",
		.fn	= test_strlcat_2,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_oslib_strlcat(void)
{
	return fio_unittest_add_suite("oslib/strlcat.c", NULL, NULL, tests);
}
