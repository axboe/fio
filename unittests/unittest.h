#ifndef FIO_UNITTEST_H
#define FIO_UNITTEST_H

#include <sys/types.h>

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

struct fio_unittest_entry {
	const char *name;
	CU_TestFunc fn;
};

CU_ErrorCode fio_unittest_add_suite(const char*, CU_InitializeFunc,
	CU_CleanupFunc, struct fio_unittest_entry*);

CU_ErrorCode fio_unittest_lib_memalign(void);
CU_ErrorCode fio_unittest_lib_strntol(void);
CU_ErrorCode fio_unittest_oslib_strlcat(void);
CU_ErrorCode fio_unittest_oslib_strndup(void);
CU_ErrorCode fio_unittest_oslib_strcasestr(void);
CU_ErrorCode fio_unittest_oslib_strsep(void);

#endif
