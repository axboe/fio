#ifndef MD5_H
#define MD5_H

#include <stdint.h>

#define MD5_DIGEST_SIZE		16
#define MD5_HMAC_BLOCK_SIZE	64
#define MD5_BLOCK_WORDS		16
#define MD5_HASH_WORDS		4

#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#define F2(x, y, z)	F1(z, x, y)
#define F3(x, y, z)	(x ^ y ^ z)
#define F4(x, y, z)	(y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, in, s) \
	(w += f(x, y, z) + in, w = (w<<s | w>>(32-s)) + x)

struct fio_md5_ctx {
	uint32_t *hash;
	uint32_t block[MD5_BLOCK_WORDS];
	uint64_t byte_count;
};

extern void fio_md5_update(struct fio_md5_ctx *, const uint8_t *, unsigned int);
extern void fio_md5_final(struct fio_md5_ctx *);
extern void fio_md5_init(struct fio_md5_ctx *);

#endif
