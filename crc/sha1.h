#ifndef FIO_SHA1
#define FIO_SHA1

/*
 * Based on the Mozilla SHA1 (see mozilla-sha1/sha1.h),
 * optimized to do word accesses rather than byte accesses,
 * and to avoid unnecessary copies into the context array.
 */

struct sha1_ctx {
	uint32_t *H;
	unsigned int W[16];
	unsigned long long size;
};

void sha1_init(struct sha1_ctx *);
void sha1_update(struct sha1_ctx *, const void *dataIn, unsigned long len);
void sha1_final(unsigned char hashout[20], struct sha1_ctx *);

#endif
