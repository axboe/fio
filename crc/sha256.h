#ifndef FIO_SHA256_H
#define FIO_SHA256_H

struct fio_sha256_ctx {
	uint32_t count[2];
	uint32_t state[8];
	uint8_t *buf;
};

void fio_sha256_init(struct fio_sha256_ctx *);
void fio_sha256_update(struct fio_sha256_ctx *, const uint8_t *, unsigned int);

#endif
