#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../fio.h"
#include "../gettime.h"
#include "../fio_time.h"
#include "../verify.h"

#include "../crc/md5.h"
#include "../crc/crc64.h"
#include "../crc/crc32.h"
#include "../crc/crc32c.h"
#include "../crc/crc16.h"
#include "../crc/crc7.h"
#include "../crc/sha1.h"
#include "../crc/sha256.h"
#include "../crc/sha512.h"
#include "../crc/xxhash.h"

#include "test.h"

#define CHUNK		131072U
#define NR_CHUNKS	  2048U

struct test_type {
	const char *name;
	unsigned int mask;
	uint64_t (*fn)(void);
};

enum {
	T_MD5		= 1U << 0,
	T_CRC64		= 1U << 1,
	T_CRC32		= 1U << 2,
	T_CRC32C	= 1U << 3,
	T_CRC16		= 1U << 4,
	T_CRC7		= 1U << 5,
	T_SHA1		= 1U << 6,
	T_SHA256	= 1U << 7,
	T_SHA512	= 1U << 8,
	T_XXHASH	= 1U << 9,
};

static void randomize_buf(void *buf, unsigned int size, int seed)
{
	struct frand_state state;

	init_rand_seed(&state, seed);
	fill_random_buf(&state, buf, size);
}

static uint64_t t_md5(void)
{
	uint32_t digest[4];
	struct fio_md5_ctx ctx = { .hash = digest };
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	fio_md5_init(&ctx);

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_md5_update(&ctx, buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_crc64(void)
{
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_crc64(buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_crc32(void)
{
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_crc32(buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_crc32c(void)
{
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_crc32c(buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_crc16(void)
{
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_crc16(buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_crc7(void)
{
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_crc7(buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_sha1(void)
{
	uint32_t sha[5];
	struct fio_sha1_ctx ctx = { .H = sha };
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	fio_sha1_init(&ctx);

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_sha1_update(&ctx, buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_sha256(void)
{
	uint8_t sha[64];
	struct fio_sha256_ctx ctx = { .buf = sha };
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	fio_sha256_init(&ctx);

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_sha256_update(&ctx, buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_sha512(void)
{
	uint8_t sha[128];
	struct fio_sha512_ctx ctx = { .buf = sha };
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	fio_sha512_init(&ctx);

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		fio_sha512_update(&ctx, buf, CHUNK);

	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static uint64_t t_xxhash(void)
{
	void *state;
	struct timeval s;
	uint64_t ret;
	void *buf;
	int i;

	state = XXH32_init(0x8989);

	buf = malloc(CHUNK);
	randomize_buf(buf, CHUNK, 0x8989);

	fio_gettime(&s, NULL);
	for (i = 0; i < NR_CHUNKS; i++)
		XXH32_update(state, buf, CHUNK);

	XXH32_digest(state);
	ret = utime_since_now(&s);
	free(buf);
	return ret;
}

static struct test_type t[] = {
	{
		.name = "md5",
		.mask = T_MD5,
		.fn = t_md5,
	},
	{
		.name = "crc64",
		.mask = T_CRC64,
		.fn = t_crc64,
	},
	{
		.name = "crc32",
		.mask = T_CRC32,
		.fn = t_crc32,
	},
	{
		.name = "crc32c",
		.mask = T_CRC32C,
		.fn = t_crc32c,
	},
	{
		.name = "crc16",
		.mask = T_CRC16,
		.fn = t_crc16,
	},
	{
		.name = "crc7",
		.mask = T_CRC7,
		.fn = t_crc7,
	},
	{
		.name = "sha1",
		.mask = T_SHA1,
		.fn = t_sha1,
	},
	{
		.name = "sha256",
		.mask = T_SHA256,
		.fn = t_sha256,
	},
	{
		.name = "sha512",
		.mask = T_SHA512,
		.fn = t_sha512,
	},
	{
		.name = "xxhash",
		.mask = T_XXHASH,
		.fn = t_xxhash,
	},
	{
		.name = NULL,
	},
};

static unsigned int get_test_mask(const char *type)
{
	char *ostr, *str = strdup(type);
	unsigned int mask;
	char *name;
	int i;

	ostr = str;
	mask = 0;
	while ((name = strsep(&str, ",")) != NULL) {
		for (i = 0; t[i].name; i++) {
			if (!strcmp(t[i].name, name)) {
				mask |= t[i].mask;
				break;
			}
		}
	}

	free(ostr);
	return mask;
}

static int list_types(void)
{
	int i;

	for (i = 0; t[i].name; i++)
		printf("%s\n", t[i].name);

	return 0;
}

int fio_crctest(const char *type)
{
	unsigned int test_mask = 0;
	uint64_t mb = CHUNK * NR_CHUNKS;
	int i;

	crc32c_intel_probe();

	if (!type)
		test_mask = ~0U;
	else if (!strcmp(type, "help") || !strcmp(type, "list"))
		return list_types();
	else
		test_mask = get_test_mask(type);

	for (i = 0; t[i].name; i++) {
		double mb_sec;
		uint64_t usec;

		if (!(t[i].mask & test_mask))
			continue;

		usec = t[i].fn();
		mb_sec = (double) mb / (double) usec;
		mb_sec /= (1.024 * 1.024);
		printf("%s:\t%.2f MB/sec\n", t[i].name, mb_sec);
	}

	return 0;
}
