#include <stdint.h>

#include "unittest.h"
#include "../optgroup.h"

static void test_libmufile_group_follows_hipfile(void)
{
	CU_ASSERT_EQUAL(__FIO_OPT_G_LIBMUFILE, __FIO_OPT_G_LIBHIPFILE + 1);
	CU_ASSERT_EQUAL(FIO_OPT_G_LIBMUFILE, (1ULL << __FIO_OPT_G_LIBMUFILE));
	CU_ASSERT_NOT_EQUAL(FIO_OPT_G_LIBMUFILE, FIO_OPT_G_LIBCUFILE);
	CU_ASSERT_NOT_EQUAL(FIO_OPT_G_LIBMUFILE, FIO_OPT_G_LIBHIPFILE);
}

static struct fio_unittest_entry tests[] = {
	{ "optgroup/libmufile", test_libmufile_group_follows_hipfile },
	{ NULL, NULL },
};

CU_ErrorCode fio_unittest_optgroup_libmufile(void)
{
	return fio_unittest_add_suite("optgroup.h", NULL, NULL, tests);
}
