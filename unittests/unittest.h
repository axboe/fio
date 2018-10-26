#ifndef FIO_UNITTEST_H
#define FIO_UNITTEST_H

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>

struct fio_unittest_entry {
	const char *name;
	CU_TestFunc fn;
};

CU_ErrorCode fio_unittest_add_suite(const char*, CU_InitializeFunc,
	CU_CleanupFunc, struct fio_unittest_entry*);

#endif
