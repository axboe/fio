#include "../fio.h"
#include "./unittest.h"

ssize_t log_err(const char *format, ...)
{
	return 0;
}

void *smalloc(size_t size)
{
	return malloc(size);
}

void *scalloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

void sfree(void *ptr)
{
	free(ptr);
}

char *smalloc_strdup(const char *str)
{
	return strdup(str);
}

void sinit(void)
{
}

void scleanup(void)
{
}

void smalloc_debug(size_t size)
{
}

unsigned int smalloc_pool_size;

struct fio_sem *fio_sem_init(int value)
{
	return NULL;
}

void fio_sem_remove(struct fio_sem *sem)
{
}

void fio_sem_down(struct fio_sem *sem)
{
}

void fio_sem_up(struct fio_sem *sem)
{
}

#include "../cgroup.c"

static char *test_path_join(const char *path, const char *name)
{
	size_t path_len = strlen(path);
	size_t name_len = strlen(name);
	size_t len = path_len + name_len + 2;
	char *joined = malloc(len);

	CU_ASSERT_PTR_NOT_NULL_FATAL(joined);
	snprintf(joined, len, "%s/%s", path, name);
	return joined;
}

static void test_get_cgroup_root_long_path(void)
{
	struct thread_data td = { 0 };
	char mnt_path[] = "/sys/fs/cgroup/blkio";
	char cgroup_name[] =
		"/system/pod51ec34a2-12b8-4a51-8b98-b49dace8366f/"
		"af7853ad741dee19af1b8e14ee2142a7a9314b2dc98a091a29f8aa96106c0a22";
	struct cgroup_mnt mnt = {
		.path = mnt_path,
		.cgroup2 = false,
	};
	char *root;
	char *expected;

	td.o.cgroup = cgroup_name;

	root = get_cgroup_root(&td, &mnt);
	CU_ASSERT_PTR_NOT_NULL_FATAL(root);

	expected = test_path_join(mnt.path, td.o.cgroup);
	CU_ASSERT_STRING_EQUAL(root, expected);
	CU_ASSERT(strlen(root) > 64);
	CU_ASSERT_EQUAL(td.error, 0);

	free(expected);
	free(root);
}

static void test_write_int_to_file_long_path(void)
{
	struct thread_data td = { 0 };
	char tmpdir[] = "/tmp/fio-cgroup-XXXXXX";
	char leaf[231];
	char *dir;
	char *file_path;
	FILE *f;
	char buf[32];

	CU_ASSERT_PTR_NOT_NULL_FATAL(mkdtemp(tmpdir));

	memset(leaf, 'x', sizeof(leaf) - 1);
	leaf[sizeof(leaf) - 1] = '\0';

	dir = test_path_join(tmpdir, leaf);
	CU_ASSERT_EQUAL_FATAL(mkdir(dir, 0700), 0);

	file_path = test_path_join(dir, "blkio.weight");
	CU_ASSERT(strlen(file_path) > 256);
	free(file_path);

	CU_ASSERT_EQUAL(write_int_to_file(&td, dir, "blkio.weight", 1234,
					  "write_int_to_file"), 0);
	CU_ASSERT_EQUAL(td.error, 0);

	file_path = test_path_join(dir, "blkio.weight");
	f = fopen(file_path, "r");
	CU_ASSERT_PTR_NOT_NULL_FATAL(f);
	CU_ASSERT_PTR_NOT_NULL(fgets(buf, sizeof(buf), f));
	CU_ASSERT_STRING_EQUAL(buf, "1234");
	fclose(f);

	CU_ASSERT_EQUAL(unlink(file_path), 0);
	CU_ASSERT_EQUAL(rmdir(dir), 0);
	CU_ASSERT_EQUAL(rmdir(tmpdir), 0);

	free(file_path);
	free(dir);
}

static struct fio_unittest_entry tests[] = {
	{
		.name	= "cgroup/get-root-long-path",
		.fn	= test_get_cgroup_root_long_path,
	},
	{
		.name	= "cgroup/write-int-to-file-long-path",
		.fn	= test_write_int_to_file_long_path,
	},
	{
		.name	= NULL,
	},
};

CU_ErrorCode fio_unittest_cgroup(void)
{
	return fio_unittest_add_suite("cgroup.c", NULL, NULL, tests);
}
