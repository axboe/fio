#include "../unittest.h"

#include "../../engines/libmufile_errno.h"

static void test_positive_and_zero_unchanged(void)
{
	CU_ASSERT_EQUAL(libmufile_translate_return(4096), 4096);
	CU_ASSERT_EQUAL(libmufile_translate_return(0), 0);
}

static void test_errno_sentinel_is_shifted(void)
{
	ssize_t shifted = libmufile_translate_return(-1);

	CU_ASSERT_EQUAL(shifted, -(ssize_t)(1 + LIBMUFILE_ERR_ALIAS));
	CU_ASSERT_NOT_EQUAL(shifted, -1);
}

static void test_other_negative_unchanged(void)
{
	CU_ASSERT_EQUAL(libmufile_translate_return(-5), -5);
	CU_ASSERT_EQUAL(libmufile_translate_return(-1001), -1001);
}

static void test_alias_restores_driver_not_initialized(void)
{
	CU_ASSERT_EQUAL(libmufile_translate_error_code(1 + LIBMUFILE_ERR_ALIAS), 1);
	CU_ASSERT_EQUAL(libmufile_translate_error_code(5), 5);
	CU_ASSERT_EQUAL(LIBMUFILE_ERR_ALIAS, 1000);
}

static struct fio_unittest_entry tests[] = {
	{ "libmufile_errno/positive", test_positive_and_zero_unchanged },
	{ "libmufile_errno/sentinel", test_errno_sentinel_is_shifted },
	{ "libmufile_errno/other", test_other_negative_unchanged },
	{ "libmufile_errno/restore", test_alias_restores_driver_not_initialized },
	{ NULL, NULL },
};

CU_ErrorCode fio_unittest_libmufile_errno(void)
{
	return fio_unittest_add_suite("engines/libmufile_errno.h", NULL, NULL, tests);
}
