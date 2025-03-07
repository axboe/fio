#include "../unittest.h"

#ifndef CONFIG_HAVE_STRNDUP
#include "../../oslib/strndup.h"
#else
#include <string.h>
#endif

static void test_strndup_1(void)
{
	char s[] = "test";
	char *p = strndup(s, 3);

	if (p) {
		CU_ASSERT_EQUAL(strcmp(p, "tes"), 0);
		CU_ASSERT_EQUAL(strlen(p), 3);
	}
}

static void test_strndup_2(void)
{
	char s[] = "test";
	char *p = strndup(s, 4);

	if (p) {
		CU_ASSERT_EQUAL(strcmp(p, s), 0);
		CU_ASSERT_EQUAL(strlen(p), 4);
	}
}

static void test_strndup_3(void)
{
	char s[] = "test";
	char *p = strndup(s, 5);

	if (p) {
		CU_ASSERT_EQUAL(strcmp(p, s), 0);
		CU_ASSERT_EQUAL(strlen(p), 4);
	}
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "strndup/1",
		.fn	= test_strndup_1,
	},
	{
		.name	= "strndup/2",
		.fn	= test_strndup_2,
	},
	{
		.name	= "strndup/3",
		.fn	= test_strndup_3,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_oslib_strndup(void)
{
	return fio_unittest_add_suite("oslib/strndup.c", NULL, NULL, tests);
}
