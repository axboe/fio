#ifndef FIO_SHA256_H
#define FIO_SHA256_H

struct sha256_ctx {
	uint32_t count[2];
	uint32_t state[8];
	uint8_t *buf;
};

void sha256_init(struct sha256_ctx *);
void sha256_update(struct sha256_ctx *, const uint8_t *, unsigned int);

#endif
