#ifndef FIO_SHA512_H
#define FIO_SHA512_H

#include <inttypes.h>

struct fio_sha512_ctx {
	uint64_t state[8];
	uint32_t count[4];
	uint8_t *buf;
	uint64_t W[80];
};

void fio_sha512_init(struct fio_sha512_ctx *);
void fio_sha512_update(struct fio_sha512_ctx *, const uint8_t *, unsigned int);

#endif
