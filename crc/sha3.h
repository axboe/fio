/*
 * Common values for SHA-3 algorithms
 */
#ifndef __CRYPTO_SHA3_H__
#define __CRYPTO_SHA3_H__

#include <inttypes.h>

#define SHA3_224_DIGEST_SIZE	(224 / 8)
#define SHA3_224_BLOCK_SIZE	(200 - 2 * SHA3_224_DIGEST_SIZE)

#define SHA3_256_DIGEST_SIZE	(256 / 8)
#define SHA3_256_BLOCK_SIZE	(200 - 2 * SHA3_256_DIGEST_SIZE)

#define SHA3_384_DIGEST_SIZE	(384 / 8)
#define SHA3_384_BLOCK_SIZE	(200 - 2 * SHA3_384_DIGEST_SIZE)

#define SHA3_512_DIGEST_SIZE	(512 / 8)
#define SHA3_512_BLOCK_SIZE	(200 - 2 * SHA3_512_DIGEST_SIZE)

struct fio_sha3_ctx {
	uint64_t	st[25];
	unsigned int	md_len;
	unsigned int	rsiz;
	unsigned int	rsizw;

	unsigned int	partial;
	uint8_t		buf[SHA3_224_BLOCK_SIZE];

	uint8_t		*sha;
};

void fio_sha3_224_init(struct fio_sha3_ctx *sctx);
void fio_sha3_256_init(struct fio_sha3_ctx *sctx);
void fio_sha3_384_init(struct fio_sha3_ctx *sctx);
void fio_sha3_512_init(struct fio_sha3_ctx *sctx);

int fio_sha3_update(struct fio_sha3_ctx *sctx, const uint8_t *data,
		    unsigned int len);
void fio_sha3_final(struct fio_sha3_ctx *sctx);

#endif
