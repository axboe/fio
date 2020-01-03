/*
 * Copyright (C) 2019 Tomohiro Kusumi <tkusumi@netbsd.org>
 */
#include "../unittest.h"

#ifndef CONFIG_STRCASESTR
#include "../../oslib/strcasestr.h"
#else
#include <string.h>
#endif

static void test_strcasestr_1(void)
{
	const char *haystack = "0123456789";
	const char *p;

	p = strcasestr(haystack, "012");
	CU_ASSERT_EQUAL(p, haystack);

	p = strcasestr(haystack, "12345");
	CU_ASSERT_EQUAL(p, haystack + 1);

	p = strcasestr(haystack, "1234567890");
	CU_ASSERT_EQUAL(p, NULL);

	p = strcasestr(haystack, "");
	CU_ASSERT_EQUAL(p, haystack); /* is this expected ? */
}

static void test_strcasestr_2(void)
{
	const char *haystack = "ABCDEFG";
	const char *p;

	p = strcasestr(haystack, "ABC");
	CU_ASSERT_EQUAL(p, haystack);

	p = strcasestr(haystack, "BCD");
	CU_ASSERT_EQUAL(p, haystack + 1);

	p = strcasestr(haystack, "ABCDEFGH");
	CU_ASSERT_EQUAL(p, NULL);

	p = strcasestr(haystack, "");
	CU_ASSERT_EQUAL(p, haystack); /* is this expected ? */
}

static void test_strcasestr_3(void)
{
	const char *haystack = "ABCDEFG";
	const char *p;

	p = strcasestr(haystack, "AbC");
	CU_ASSERT_EQUAL(p, haystack);

	p = strcasestr(haystack, "bCd");
	CU_ASSERT_EQUAL(p, haystack + 1);

	p = strcasestr(haystack, "AbcdEFGH");
	CU_ASSERT_EQUAL(p, NULL);

	p = strcasestr(haystack, "");
	CU_ASSERT_EQUAL(p, haystack); /* is this expected ? */
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "strcasestr/1",
		.fn	= test_strcasestr_1,
	},
	{
		.name	= "strcasestr/2",
		.fn	= test_strcasestr_2,
	},
	{
		.name	= "strcasestr/3",
		.fn	= test_strcasestr_3,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_oslib_strcasestr(void)
{
	return fio_unittest_add_suite("oslib/strcasestr.c", NULL, NULL, tests);
}
