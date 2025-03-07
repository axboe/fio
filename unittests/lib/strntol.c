#include "../unittest.h"

#include "../../lib/strntol.h"

static void test_strntol_1(void)
{
	char s[] = "12345";
	char *endp = NULL;
	long ret = strntol(s, strlen(s), &endp, 10);

	CU_ASSERT_EQUAL(ret, 12345);
	CU_ASSERT_NOT_EQUAL(endp, NULL);
	CU_ASSERT_EQUAL(*endp, '\0');
}

static void test_strntol_2(void)
{
	char s[] = "     12345";
	char *endp = NULL;
	long ret = strntol(s, strlen(s), &endp, 10);

	CU_ASSERT_EQUAL(ret, 12345);
	CU_ASSERT_NOT_EQUAL(endp, NULL);
	CU_ASSERT_EQUAL(*endp, '\0');
}

static void test_strntol_3(void)
{
	char s[] = "0x12345";
	char *endp = NULL;
	long ret = strntol(s, strlen(s), &endp, 16);

	CU_ASSERT_EQUAL(ret, 0x12345);
	CU_ASSERT_NOT_EQUAL(endp, NULL);
	CU_ASSERT_EQUAL(*endp, '\0');
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "strntol/1",
		.fn	= test_strntol_1,
	},
	{
		.name	= "strntol/2",
		.fn	= test_strntol_2,
	},
	{
		.name	= "strntol/3",
		.fn	= test_strntol_3,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_lib_strntol(void)
{
	return fio_unittest_add_suite("lib/strntol.c", NULL, NULL, tests);
}
