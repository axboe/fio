#ifndef FIO_VERIFY_H
#define FIO_VERIFY_H

#include <stdint.h>
#include "verify-state.h"

#define FIO_HDR_MAGIC	0xacca

enum {
	VERIFY_NONE = 0,		/* no verification */
	VERIFY_HDR_ONLY,		/* verify header only, kept for sake of
					 * compatibility with old configurations
					 * which use 'verify=meta' */
	VERIFY_MD5,			/* md5 sum data blocks */
	VERIFY_CRC64,			/* crc64 sum data blocks */
	VERIFY_CRC32,			/* crc32 sum data blocks */
	VERIFY_CRC32C,			/* crc32c sum data blocks */
	VERIFY_CRC32C_INTEL,		/* crc32c sum data blocks with hw */
	VERIFY_CRC16,			/* crc16 sum data blocks */
	VERIFY_CRC7,			/* crc7 sum data blocks */
	VERIFY_SHA256,			/* sha256 sum data blocks */
	VERIFY_SHA512,			/* sha512 sum data blocks */
	VERIFY_SHA3_224,		/* sha3-224 sum data blocks */
	VERIFY_SHA3_256,		/* sha3-256 sum data blocks */
	VERIFY_SHA3_384,		/* sha3-384 sum data blocks */
	VERIFY_SHA3_512,		/* sha3-512 sum data blocks */
	VERIFY_XXHASH,			/* xxhash sum data blocks */
	VERIFY_SHA1,			/* sha1 sum data blocks */
	VERIFY_PATTERN,			/* verify specific patterns */
	VERIFY_PATTERN_NO_HDR,		/* verify specific patterns, no hdr */
	VERIFY_NULL,			/* pretend to verify */
};

/*
 * A header structure associated with each checksummed data block. It is
 * followed by a checksum specific header that contains the verification
 * data.
 */
struct verify_header {
	uint16_t magic;
	uint16_t verify_type;
	uint32_t len;
	uint64_t rand_seed;
	uint64_t offset;
	uint32_t time_sec;
	uint32_t time_usec;
	uint16_t thread;
	uint16_t numberio;
	uint32_t crc32;
};

struct vhdr_md5 {
	uint32_t md5_digest[4];
};
struct vhdr_sha3_224 {
	uint8_t sha[224 / 8];
};
struct vhdr_sha3_256 {
	uint8_t sha[256 / 8];
};
struct vhdr_sha3_384 {
	uint8_t sha[384 / 8];
};
struct vhdr_sha3_512 {
	uint8_t sha[512 / 8];
};
struct vhdr_sha512 {
	uint8_t sha512[128];
};
struct vhdr_sha256 {
	uint8_t sha256[64];
};
struct vhdr_sha1 {
	uint32_t sha1[5];
};
struct vhdr_crc64 {
	uint64_t crc64;
};
struct vhdr_crc32 {
	uint32_t crc32;
};
struct vhdr_crc16 {
	uint16_t crc16;
};
struct vhdr_crc7 {
	uint8_t crc7;
};
struct vhdr_xxhash {
	uint32_t hash;
};

/*
 * Verify helpers
 */
extern void populate_verify_io_u(struct thread_data *, struct io_u *);
extern int __must_check get_next_verify(struct thread_data *td, struct io_u *);
extern int __must_check verify_io_u(struct thread_data *, struct io_u **);
extern int verify_io_u_async(struct thread_data *, struct io_u **);
extern void fill_verify_pattern(struct thread_data *td, void *p, unsigned int len, struct io_u *io_u, unsigned long seed, int use_seed);
extern void fill_buffer_pattern(struct thread_data *td, void *p, unsigned int len);
extern void fio_verify_init(struct thread_data *td);

/*
 * Async verify offload
 */
extern int verify_async_init(struct thread_data *);
extern void verify_async_exit(struct thread_data *);

/*
 * Callbacks for pasting formats in the pattern buffer
 */
extern int paste_blockoff(char *buf, unsigned int len, void *priv);

#endif
