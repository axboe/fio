#ifndef FIO_SHA512_H
#define FIO_SHA512_H

struct sha512_ctx {
	uint64_t state[8];
	uint32_t count[4];
	uint8_t *buf;
	uint64_t W[80];
};

void sha512_init(struct sha512_ctx *);
void sha512_update(struct sha512_ctx *, const uint8_t *, unsigned int);

#endif
