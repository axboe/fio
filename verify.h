#ifndef FIO_VERIFY_H
#define FIO_VERIFY_H

#include <stdint.h>

#define FIO_HDR_MAGIC	0xacca

enum {
	VERIFY_NONE = 0,		/* no verification */
	VERIFY_MD5,			/* md5 sum data blocks */
	VERIFY_CRC64,			/* crc64 sum data blocks */
	VERIFY_CRC32,			/* crc32 sum data blocks */
	VERIFY_CRC32C,			/* crc32c sum data blocks */
	VERIFY_CRC32C_INTEL,		/* crc32c sum data blocks with hw */
	VERIFY_CRC16,			/* crc16 sum data blocks */
	VERIFY_CRC7,			/* crc7 sum data blocks */
	VERIFY_SHA256,			/* sha256 sum data blocks */
	VERIFY_SHA512,			/* sha512 sum data blocks */
	VERIFY_XXHASH,			/* xxhash sum data blocks */
	VERIFY_META,			/* block_num, timestamp etc. */
	VERIFY_SHA1,			/* sha1 sum data blocks */
	VERIFY_PATTERN,			/* verify specific patterns */
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
	uint32_t crc32;
};

struct vhdr_md5 {
	uint32_t md5_digest[4];
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
struct vhdr_meta {
	uint64_t offset;
	unsigned char thread;
	unsigned short numberio;
	unsigned long time_sec;
	unsigned long time_usec;
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

struct thread_rand_state {
	uint32_t s[4];
};

/*
 * For dumping current write state
 */
struct thread_io_list {
	uint64_t no_comps;
	uint64_t depth;
	uint64_t numberio;
	uint64_t index;
	struct thread_rand_state rand;
	uint8_t name[64];
	uint64_t offsets[0];
};

struct all_io_list {
	uint64_t threads;
	struct thread_io_list state[0];
};

#define VSTATE_HDR_VERSION	0x01

struct verify_state_hdr {
	uint64_t version;
	uint64_t size;
	uint64_t crc;
};

#define IO_LIST_ALL		0xffffffff
extern struct all_io_list *get_all_io_list(int, size_t *);
extern void __verify_save_state(struct all_io_list *, const char *);
extern void verify_save_state(void);
extern int verify_load_state(struct thread_data *, const char *);
extern void verify_free_state(struct thread_data *);
extern int verify_state_should_stop(struct thread_data *, struct io_u *);
extern void verify_convert_assign_state(struct thread_data *, struct thread_io_list *);
extern int verify_state_hdr(struct verify_state_hdr *, struct thread_io_list *);

static inline size_t thread_io_list_sz(struct thread_io_list *s)
{
	return sizeof(*s) + le64_to_cpu(s->depth) * sizeof(uint64_t);
}

static inline struct thread_io_list *io_list_next(struct thread_io_list *s)
{
	return (void *) s + thread_io_list_sz(s);
}

static inline void verify_state_gen_name(char *out, size_t size,
					 const char *name, const char *prefix,
					 int num)
{
	snprintf(out, size, "%s-%s-%d-verify.state", prefix, name, num);
	out[size - 1] = '\0';
}

#endif
