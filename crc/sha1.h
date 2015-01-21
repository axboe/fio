#ifndef FIO_SHA1
#define FIO_SHA1

/*
 * Based on the Mozilla SHA1 (see mozilla-sha1/sha1.h),
 * optimized to do word accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 */

struct fio_sha1_ctx {
	uint32_t *H;
	unsigned int W[16];
	unsigned long long size;
};

void fio_sha1_init(struct fio_sha1_ctx *);
void fio_sha1_update(struct fio_sha1_ctx *, const void *dataIn, unsigned long len);
void fio_sha1_final(struct fio_sha1_ctx *);

#endif
