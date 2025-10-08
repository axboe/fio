#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../os/os.h"
#include "../gettime.h"
#include "../fio_time.h"
#include "../lib/rand.h"

#include "../crc/md5.h"
#include "../crc/crc64.h"
#include "../crc/crc32.h"
#include "../crc/crc32c.h"
#include "../crc/crc16.h"
#include "../crc/crc7.h"
#include "../crc/sha1.h"
#include "../crc/sha256.h"
#include "../crc/sha512.h"
#include "../crc/sha3.h"
#include "../crc/xxhash.h"
#include "../crc/murmur3.h"
#include "../crc/fnv.h"
#include "../hash.h"

#include "test.h"

#define CHUNK		131072U
#define NR_CHUNKS	  2048U

struct test_type {
	const char *name;
	unsigned int mask;
	void (*fn)(struct test_type *, void *, size_t);
	uint32_t output;
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
	T_MURMUR3	= 1U << 10,
	T_JHASH		= 1U << 11,
	T_FNV		= 1U << 12,
	T_SHA3_224	= 1U << 13,
	T_SHA3_256	= 1U << 14,
	T_SHA3_384	= 1U << 15,
	T_SHA3_512	= 1U << 16,
};

static void t_md5(struct test_type *t, void *buf, size_t size)
{
	uint32_t digest[4];
	struct fio_md5_ctx ctx = { .hash = digest };
	int i;

	fio_md5_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_md5_update(&ctx, buf, size);
		fio_md5_final(&ctx);
	}
}

static void t_crc64(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fio_crc64(buf, size);
}

static void t_crc32(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fio_crc32(buf, size);
}

static void t_crc32c(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fio_crc32c(buf, size);
}

static void t_crc16(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fio_crc16(buf, size);
}

static void t_crc7(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fio_crc7(buf, size);
}

static void t_sha1(struct test_type *t, void *buf, size_t size)
{
	uint32_t sha[5];
	struct fio_sha1_ctx ctx = { .H = sha };
	int i;

	fio_sha1_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha1_update(&ctx, buf, size);
		fio_sha1_final(&ctx);
	}
}

static void t_sha256(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[64];
	struct fio_sha256_ctx ctx = { .buf = sha };
	int i;

	fio_sha256_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha256_update(&ctx, buf, size);
		fio_sha256_final(&ctx);
	}
}

static void t_sha512(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[128];
	struct fio_sha512_ctx ctx = { .buf = sha };
	int i;

	fio_sha512_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++)
		fio_sha512_update(&ctx, buf, size);
}

static void t_sha3_224(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[SHA3_224_DIGEST_SIZE];
	struct fio_sha3_ctx ctx = { .sha = sha };
	int i;

	fio_sha3_224_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha3_update(&ctx, buf, size);
		fio_sha3_final(&ctx);
	}
}

static void t_sha3_256(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[SHA3_256_DIGEST_SIZE];
	struct fio_sha3_ctx ctx = { .sha = sha };
	int i;

	fio_sha3_256_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha3_update(&ctx, buf, size);
		fio_sha3_final(&ctx);
	}
}

static void t_sha3_384(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[SHA3_384_DIGEST_SIZE];
	struct fio_sha3_ctx ctx = { .sha = sha };
	int i;

	fio_sha3_384_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha3_update(&ctx, buf, size);
		fio_sha3_final(&ctx);
	}
}

static void t_sha3_512(struct test_type *t, void *buf, size_t size)
{
	uint8_t sha[SHA3_512_DIGEST_SIZE];
	struct fio_sha3_ctx ctx = { .sha = sha };
	int i;

	fio_sha3_512_init(&ctx);

	for (i = 0; i < NR_CHUNKS; i++) {
		fio_sha3_update(&ctx, buf, size);
		fio_sha3_final(&ctx);
	}
}

static void t_murmur3(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += murmurhash3(buf, size, 0x8989);
}

static void t_jhash(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += jhash(buf, size, 0x8989);
}

static void t_fnv(struct test_type *t, void *buf, size_t size)
{
	int i;

	for (i = 0; i < NR_CHUNKS; i++)
		t->output += fnv(buf, size, 0x8989);
}

static void t_xxhash(struct test_type *t, void *buf, size_t size)
{
	void *state;
	int i;

	state = XXH32_init(0x8989);

	for (i = 0; i < NR_CHUNKS; i++)
		XXH32_update(state, buf, size);

	t->output = XXH32_digest(state);
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
		.name = "murmur3",
		.mask = T_MURMUR3,
		.fn = t_murmur3,
	},
	{
		.name = "jhash",
		.mask = T_JHASH,
		.fn = t_jhash,
	},
	{
		.name = "fnv",
		.mask = T_FNV,
		.fn = t_fnv,
	},
	{
		.name = "sha3-224",
		.mask = T_SHA3_224,
		.fn = t_sha3_224,
	},
	{
		.name = "sha3-256",
		.mask = T_SHA3_256,
		.fn = t_sha3_256,
	},
	{
		.name = "sha3-384",
		.mask = T_SHA3_384,
		.fn = t_sha3_384,
	},
	{
		.name = "sha3-512",
		.mask = T_SHA3_512,
		.fn = t_sha3_512,
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

	return 1;
}

int fio_crctest(const char *type)
{
	unsigned int test_mask = 0;
	uint64_t mb = CHUNK * NR_CHUNKS;
	struct frand_state state;
	int i, first = 1;
	void *buf;

	crc32c_arm64_probe();
	crc32c_intel_probe();

	if (!type)
		test_mask = ~0U;
	else if (!strcmp(type, "help") || !strcmp(type, "list"))
		return list_types();
	else
		test_mask = get_test_mask(type);

	if (!test_mask) {
		fprintf(stderr, "fio: unknown hash `%s`. Available:\n", type);
		return list_types();
	}

	buf = malloc(CHUNK);
	init_rand_seed(&state, 0x8989, 0);
	fill_random_buf(&state, buf, CHUNK);

	for (i = 0; t[i].name; i++) {
		struct timespec ts;
		double mb_sec;
		uint64_t usec;
		char pre[3];

		if (!(t[i].mask & test_mask))
			continue;

		/*
		 * For first run, make sure CPUs are spun up and that
		 * we've touched the data.
		 */
		if (first) {
			usec_spin(100000);
			t[i].fn(&t[i], buf, CHUNK);
		}

		fio_gettime(&ts, NULL);
		t[i].fn(&t[i], buf, CHUNK);
		usec = utime_since_now(&ts);

		if (usec) {
			mb_sec = (double) mb / (double) usec;
			mb_sec /= (1.024 * 1.024);
			if (strlen(t[i].name) >= 7)
				sprintf(pre, "\t");
			else
				sprintf(pre, "\t\t");
			printf("%s:%s%8.2f MiB/sec\n", t[i].name, pre, mb_sec);
		} else
			printf("%s:inf MiB/sec\n", t[i].name);
		first = 0;
	}

	free(buf);
	return 0;
}
