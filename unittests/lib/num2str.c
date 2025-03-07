#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include "../../compiler/compiler.h"
#include "../../lib/num2str.h"
#include "../unittest.h"

struct testcase {
	uint64_t num;
	int maxlen;
	int base;
	int pow2;
	enum n2s_unit unit;
	const char *expected;
};

static const struct testcase testcases[] = {
	{ 1, 1, 1, 0, N2S_NONE, "1" },
	{ UINT64_MAX, 99, 1, 0, N2S_NONE, "18446744073709551615" },
	{ 18446744073709551, 2, 1, 0, N2S_NONE, "18P" },
	{ 18446744073709551, 4, 1, 0, N2S_NONE, "18.4P" },
	{ UINT64_MAX, 2, 1, 0, N2S_NONE, "18E" },
	{ UINT64_MAX, 4, 1, 0, N2S_NONE, "18.4E" },
};

static void test_num2str(void)
{
	const struct testcase *p;
	char *str;
	int i;

	for (i = 0; i < FIO_ARRAY_SIZE(testcases); ++i) {
		p = &testcases[i];
		str = num2str(p->num, p->maxlen, p->base, p->pow2, p->unit);
		CU_ASSERT_STRING_EQUAL(str, p->expected);
		free(str);
	}
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "num2str/1",
		.fn	= test_num2str,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_lib_num2str(void)
{
	return fio_unittest_add_suite("lib/num2str.c", NULL, NULL, tests);
}
