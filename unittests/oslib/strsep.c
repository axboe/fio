/*
 * Copyright (C) 2019 Tomohiro Kusumi <tkusumi@netbsd.org>
 */
#include "../unittest.h"

#ifndef CONFIG_STRSEP
#include "../../oslib/strsep.h"
#else
#include <string.h>
#endif

/*
 * strsep(3) - "If *stringp is NULL, the strsep() function returns NULL and does
 * nothing else."
 */
static void test_strsep_1(void)
{
	char *string = NULL;
	const char *p;

	p = strsep(&string, "");
	CU_ASSERT_EQUAL(p, NULL);
	CU_ASSERT_EQUAL(string, NULL);

	p = strsep(&string, "ABC");
	CU_ASSERT_EQUAL(p, NULL);
	CU_ASSERT_EQUAL(string, NULL);
}

/*
 * strsep(3) - "In case no delimiter was found, the token is taken to be the
 * entire string *stringp, and *stringp is made NULL."
 */
static void test_strsep_2(void)
{
	char src[] = "ABCDEFG";
	char *string = src;
	const char *p;

	p = strsep(&string, "");
	CU_ASSERT_EQUAL(p, src);
	CU_ASSERT_EQUAL(*p, 'A');
	CU_ASSERT_EQUAL(string, NULL);

	string = src;
	p = strsep(&string, "@");
	CU_ASSERT_EQUAL(p, src);
	CU_ASSERT_EQUAL(*p, 'A');
	CU_ASSERT_EQUAL(string, NULL);
}

/*
 * strsep(3) - "This token is terminated with a '\0' character (by overwriting
 * the delimiter) and *stringp is updated to point past the token."
 */
static void test_strsep_3(void)
{
	char src[] = "ABCDEFG";
	char *string = src;
	const char *p;

	p = strsep(&string, "ABC");
	CU_ASSERT_EQUAL(p, &src[0]);
	CU_ASSERT_EQUAL(*p, '\0');
	CU_ASSERT_EQUAL(strcmp(string, "BCDEFG"), 0);
	CU_ASSERT_EQUAL(*string, 'B');

	p = strsep(&string, "ABC");
	CU_ASSERT_EQUAL(p, &src[1]);
	CU_ASSERT_EQUAL(*p, '\0');
	CU_ASSERT_EQUAL(strcmp(string, "CDEFG"), 0);
	CU_ASSERT_EQUAL(*string, 'C');

	p = strsep(&string, "ABC");
	CU_ASSERT_EQUAL(p, &src[2]);
	CU_ASSERT_EQUAL(*p, '\0');
	CU_ASSERT_EQUAL(strcmp(string, "DEFG"), 0);
	CU_ASSERT_EQUAL(*string, 'D');

	p = strsep(&string, "ABC");
	CU_ASSERT_EQUAL(p, &src[3]);
	CU_ASSERT_EQUAL(*p, 'D');
	CU_ASSERT_EQUAL(string, NULL);
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "strsep/1",
		.fn	= test_strsep_1,
	},
	{
		.name	= "strsep/2",
		.fn	= test_strsep_2,
	},
	{
		.name	= "strsep/3",
		.fn	= test_strsep_3,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_oslib_strsep(void)
{
	return fio_unittest_add_suite("oslib/strsep.c", NULL, NULL, tests);
}
