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

struct bytes2str_testcase {
        uint64_t bytes;
        const char *expected;
};

static const struct bytes2str_testcase bytes2str_testcases[] = {
        { 0, "0.00 B" },
        { 512, "512.00 B" },
        { 1024, "1.00 KiB" },
        { 1536, "1.50 KiB" },
        { 1048576, "1.00 MiB" },
        { 1073741824ULL, "1.00 GiB" },
        { 1099511627776ULL, "1.00 TiB" },
        { 1125899906842624ULL, "1.00 PiB" },
        { 1152921504606846976ULL, "1.00 EiB" },
};

static void test_bytes2str_simple(void)
{
        char buf[64];
        int i;

        for (i = 0; i < FIO_ARRAY_SIZE(bytes2str_testcases); ++i) {
                const struct bytes2str_testcase *tc = &bytes2str_testcases[i];
                const char *result = bytes2str_simple(buf, sizeof(buf), tc->bytes);

                CU_ASSERT_PTR_EQUAL(result, buf);
                CU_ASSERT_STRING_EQUAL(result, tc->expected);
        }
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "num2str/1",
		.fn	= test_num2str,
	},
	{
                .name   = "bytes2str_simple/1",
                .fn     = test_bytes2str_simple,
        },
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_lib_num2str(void)
{
	return fio_unittest_add_suite("lib/num2str.c", NULL, NULL, tests);
}
