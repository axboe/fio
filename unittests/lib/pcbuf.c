/**
 * SPDX-License-Identifier: GPL-2.0 only
 *
 * Copyright (c) 2025 Sandisk Corporation or its affiliates.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "../unittest.h"
#include "pcbuf.h"

#define TEST_CAPACITY 8  /* Small capacity for wrap-around testing */

static void test_pcbuf_basic_ops(void)
{
	struct pc_buf *cb = pcb_alloc(TEST_CAPACITY);
	uint64_t i;

	CU_ASSERT_PTR_NOT_NULL(cb);

	CU_ASSERT_TRUE(pcb_is_empty(cb));
	CU_ASSERT_FALSE(pcb_is_full(cb));
	CU_ASSERT_EQUAL(pcb_committed_size(cb), 0);
	CU_ASSERT_EQUAL(pcb_staged_size(cb), 0);
	CU_ASSERT_TRUE(pcb_space_available(cb));

	/* Stage data up to capacity-1 (since 1 slot is reserved) */
	for (i = 0; i < TEST_CAPACITY - 1; ++i) {
		CU_ASSERT_TRUE(pcb_push_staged(cb, i + 100));
	}

	/* Next push should fail (buffer full) */
	CU_ASSERT_FALSE(pcb_push_staged(cb, 999));

	CU_ASSERT_EQUAL(pcb_staged_size(cb), TEST_CAPACITY - 1);
	CU_ASSERT_EQUAL(pcb_committed_size(cb), 0);
	CU_ASSERT_TRUE(pcb_is_empty(cb));
	CU_ASSERT_TRUE(pcb_is_full(cb));

	/* Commit staged data */
	pcb_commit(cb);

	CU_ASSERT_EQUAL(pcb_committed_size(cb), TEST_CAPACITY - 1);
	CU_ASSERT_EQUAL(pcb_staged_size(cb), 0);
	CU_ASSERT_FALSE(pcb_is_empty(cb));

	/* Pop all committed data */
	for (i = 0; i < TEST_CAPACITY - 1; ++i) {
		uint64_t val;
		CU_ASSERT_TRUE(pcb_pop(cb, &val));
		CU_ASSERT_EQUAL(val, i + 100);
	}

	/* Buffer should now be empty again */
	CU_ASSERT_TRUE(pcb_is_empty(cb));
	CU_ASSERT_FALSE(pcb_is_full(cb));
	CU_ASSERT_TRUE(pcb_space_available(cb));

	free(cb);
}

static void test_pcbuf_wraparound(void)
{
	struct pc_buf *cb = pcb_alloc(TEST_CAPACITY);
	uint64_t expected[] = {201, 202, 203, 204, 205, 999};
	size_t num_expected = sizeof(expected)/sizeof(expected[0]);
	uint64_t val;
	uint64_t i;

	CU_ASSERT_PTR_NOT_NULL(cb);

	/* Stage up to near capacity and commit */
	for (i = 0; i < TEST_CAPACITY - 2; ++i)
		CU_ASSERT_TRUE(pcb_push_staged(cb, i + 200));

	pcb_commit(cb);

	/* Pop one item to move read_tail forward */
	CU_ASSERT_TRUE(pcb_pop(cb, &val));
	CU_ASSERT_EQUAL(val, 200);

	/* Now stage one more item to cause wraparound */
	CU_ASSERT_TRUE(pcb_push_staged(cb, 999));
	pcb_commit(cb);

	/* Pop remaining items, ensure correctness */
	for (i = 0; i < num_expected; ++i) {
		CU_ASSERT_TRUE(pcb_pop(cb, &val));
		CU_ASSERT_EQUAL(val, expected[i]);
	}

	CU_ASSERT_TRUE(pcb_is_empty(cb));
	free(cb);
}

static struct fio_unittest_entry tests[] = {
	{
		.name   = "pcbuf/basic_ops",
		.fn     = test_pcbuf_basic_ops,
	},
	{
		.name   = "pcbuf/wraparound",
		.fn     = test_pcbuf_wraparound,
	},
	{
		.name   = NULL,
	},
};

CU_ErrorCode fio_unittest_lib_pcbuf(void)
{
	return fio_unittest_add_suite("pcbuf.h", NULL, NULL, tests);
}
