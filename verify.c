/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <libgen.h>

#include "arch/arch.h"
#include "fio.h"
#include "verify.h"
#include "trim.h"
#include "lib/rand.h"
#include "lib/hweight.h"
#include "lib/pattern.h"
#include "oslib/asprintf.h"

#include "crc/md5.h"
#include "crc/crc64.h"
#include "crc/crc32.h"
#include "crc/crc32c.h"
#include "crc/crc16.h"
#include "crc/crc7.h"
#include "crc/sha256.h"
#include "crc/sha512.h"
#include "crc/sha1.h"
#include "crc/xxhash.h"
#include "crc/sha3.h"

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len);
static void __fill_hdr(struct thread_data *td, struct io_u *io_u,
		       struct verify_header *hdr, unsigned int header_num,
		       unsigned int header_len, uint64_t rand_seed);

void fill_buffer_pattern(struct thread_data *td, void *p, unsigned int len)
{
	(void)cpy_pattern(td->o.buffer_pattern, td->o.buffer_pattern_bytes, p, len);
}

static void __fill_buffer(struct thread_options *o, uint64_t seed, void *p,
			  unsigned int len)
{
	__fill_random_buf_percentage(seed, p, o->compress_percentage, len, len, o->buffer_pattern, o->buffer_pattern_bytes);
}

void fill_verify_pattern(struct thread_data *td, void *p, unsigned int len,
			 struct io_u *io_u, uint64_t seed, int use_seed)
{
	struct thread_options *o = &td->o;
	unsigned int interval = o->verify_pattern_interval;
	unsigned long long offset = io_u->offset;

	if (!o->verify_pattern_bytes) {
		dprint(FD_VERIFY, "fill random bytes len=%u\n", len);

		if (!use_seed) {
			seed = __rand(&td->verify_state);
			if (sizeof(int) != sizeof(long *))
				seed *= (unsigned long)__rand(&td->verify_state);
		}
		io_u->rand_seed = seed;
		__fill_buffer(o, seed, p, len);
		return;
	}

	/* Skip if we were here and we do not need to patch pattern with
	 * format. However, we cannot skip if verify_offset is set because we
	 * have swapped the header with pattern bytes */
	if (!td->o.verify_fmt_sz && io_u->buf_filled_len >= len && !td->o.verify_offset) {
		dprint(FD_VERIFY, "using already filled verify pattern b=%d len=%u\n",
			o->verify_pattern_bytes, len);
		return;
	}

	if (!interval)
		interval = len;

	io_u->offset += (p - io_u->buf) - (p - io_u->buf) % interval;
	for (unsigned int bytes_done = 0, bytes_todo = 0; bytes_done < len;
			bytes_done += bytes_todo, p += bytes_todo, io_u->offset += interval) {
		bytes_todo = (p - io_u->buf) % interval;
		if (!bytes_todo)
			bytes_todo = interval;
		bytes_todo = min(bytes_todo, len - bytes_done);

		(void)paste_format(td->o.verify_pattern, td->o.verify_pattern_bytes,
				   td->o.verify_fmt, td->o.verify_fmt_sz,
				   p, bytes_todo, io_u);
	}

	io_u->buf_filled_len = len;
	io_u->offset = offset;
}

static unsigned int get_hdr_inc(struct thread_data *td, struct io_u *io_u)
{
	unsigned int hdr_inc;

	/*
	 * If we use bs_unaligned, buflen can be larger than the verify
	 * interval (which just defaults to the smallest blocksize possible).
	 */
	hdr_inc = io_u->buflen;
	if (td->o.verify_interval && td->o.verify_interval <= io_u->buflen &&
	    !td->o.bs_unaligned)
		hdr_inc = td->o.verify_interval;

	return hdr_inc;
}

static void fill_pattern_headers(struct thread_data *td, struct io_u *io_u,
				 uint64_t seed, int use_seed)
{
	unsigned int hdr_inc, header_num;
	struct verify_header *hdr;
	void *p = io_u->buf;

	fill_verify_pattern(td, p, io_u->buflen, io_u, seed, use_seed);

	hdr_inc = get_hdr_inc(td, io_u);
	header_num = 0;
	for (; p < io_u->buf + io_u->buflen; p += hdr_inc) {
		hdr = p;
		populate_hdr(td, io_u, hdr, header_num, hdr_inc);
		header_num++;
	}
}

static void memswp(void *buf1, void *buf2, unsigned int len)
{
	char swap[200];

	assert(len <= sizeof(swap));

	memcpy(&swap, buf1, len);
	memcpy(buf1, buf2, len);
	memcpy(buf2, &swap, len);
}

static void hexdump(void *buffer, int len)
{
	unsigned char *p = buffer;
	int i;

	for (i = 0; i < len; i++)
		log_err("%02x", p[i]);
	log_err("\n");
}

/*
 * Prepare for separation of verify_header and checksum header
 */
static inline unsigned int __hdr_size(int verify_type)
{
	unsigned int len = 0;

	switch (verify_type) {
	case VERIFY_NONE:
	case VERIFY_HDR_ONLY:
	case VERIFY_NULL:
	case VERIFY_PATTERN:
		len = 0;
		break;
	case VERIFY_MD5:
		len = sizeof(struct vhdr_md5);
		break;
	case VERIFY_CRC64:
		len = sizeof(struct vhdr_crc64);
		break;
	case VERIFY_CRC32C:
	case VERIFY_CRC32:
	case VERIFY_CRC32C_INTEL:
		len = sizeof(struct vhdr_crc32);
		break;
	case VERIFY_CRC16:
		len = sizeof(struct vhdr_crc16);
		break;
	case VERIFY_CRC7:
		len = sizeof(struct vhdr_crc7);
		break;
	case VERIFY_SHA256:
		len = sizeof(struct vhdr_sha256);
		break;
	case VERIFY_SHA512:
		len = sizeof(struct vhdr_sha512);
		break;
	case VERIFY_SHA3_224:
		len = sizeof(struct vhdr_sha3_224);
		break;
	case VERIFY_SHA3_256:
		len = sizeof(struct vhdr_sha3_256);
		break;
	case VERIFY_SHA3_384:
		len = sizeof(struct vhdr_sha3_384);
		break;
	case VERIFY_SHA3_512:
		len = sizeof(struct vhdr_sha3_512);
		break;
	case VERIFY_XXHASH:
		len = sizeof(struct vhdr_xxhash);
		break;
	case VERIFY_SHA1:
		len = sizeof(struct vhdr_sha1);
		break;
	case VERIFY_PATTERN_NO_HDR:
		return 0;
	default:
		log_err("fio: unknown verify header!\n");
		assert(0);
	}

	return len + sizeof(struct verify_header);
}

static inline unsigned int hdr_size(struct thread_data *td,
				    struct verify_header *hdr)
{
	if (td->o.verify == VERIFY_PATTERN_NO_HDR)
		return 0;

	return __hdr_size(hdr->verify_type);
}

static void *hdr_priv(struct verify_header *hdr)
{
	void *priv = hdr;

	return priv + sizeof(struct verify_header);
}

/*
 * Verify container, pass info to verify handlers and allow them to
 * pass info back in case of error
 */
struct vcont {
	/*
	 * Input
	 */
	struct io_u *io_u;
	unsigned int hdr_num;
	struct thread_data *td;

	/*
	 * Output, only valid in case of error
	 */
	const char *name;
	void *good_crc;
	void *bad_crc;
	unsigned int crc_len;
};

#define DUMP_BUF_SZ	255

static void dump_buf(char *buf, unsigned int len, unsigned long long offset,
		     const char *type, struct fio_file *f)
{
	char *ptr, *fname;
	char sep[2] = { FIO_OS_PATH_SEPARATOR, 0 };
	int ret, fd;

	ptr = strdup(f->file_name);

	if (asprintf(&fname, "%s%s%s.%llu.%s", aux_path ? : "",
		     aux_path ? sep : "", basename(ptr), offset, type) < 0) {
		if (!fio_did_warn(FIO_WARN_VERIFY_BUF))
			log_err("fio: not enough memory for dump buffer filename\n");
		goto free_ptr;
	}

	fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		perror("open verify buf file");
		goto free_fname;
	}

	while (len) {
		ret = write(fd, buf, len);
		if (!ret)
			break;
		else if (ret < 0) {
			perror("write verify buf file");
			break;
		}
		len -= ret;
		buf += ret;
	}

	close(fd);
	log_err("       %s data dumped as %s\n", type, fname);

free_fname:
	free(fname);

free_ptr:
	free(ptr);
}

/*
 * Dump the contents of the read block and re-generate the correct data
 * and dump that too.
 */
static void __dump_verify_buffers(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	unsigned long hdr_offset;
	struct io_u dummy;
	void *buf;

	if (!td->o.verify_dump)
		return;

	/*
	 * Dump the contents we just read off disk
	 */
	hdr_offset = vc->hdr_num * hdr->len;

	dump_buf(io_u->buf + hdr_offset, hdr->len, io_u->verify_offset + hdr_offset,
			"received", vc->io_u->file);

	/*
	 * Allocate a new buf and re-generate the original data
	 */
	buf = malloc(io_u->buflen);
	dummy = *io_u;
	dummy.buf = buf;
	dummy.rand_seed = hdr->rand_seed;
	dummy.buf_filled_len = 0;
	dummy.buflen = io_u->buflen;

	fill_pattern_headers(td, &dummy, hdr->rand_seed, 1);

	dump_buf(buf + hdr_offset, hdr->len, io_u->verify_offset + hdr_offset,
			"expected", vc->io_u->file);
	free(buf);
}

static void dump_verify_buffers(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct verify_header shdr;

	if (td->o.verify == VERIFY_PATTERN_NO_HDR) {
		__fill_hdr(td, vc->io_u, &shdr, 0, vc->io_u->buflen, 0);
		hdr = &shdr;
	}

	__dump_verify_buffers(hdr, vc);
}

static void log_verify_failure(struct verify_header *hdr, struct vcont *vc)
{
	unsigned long long offset;
	uint32_t len;
	struct thread_data *td = vc->td;

	offset = vc->io_u->verify_offset;
	if (td->o.verify != VERIFY_PATTERN_NO_HDR) {
		len = hdr->len;
		offset += (unsigned long long) vc->hdr_num * len;
	} else {
		len = vc->io_u->buflen;
	}

	log_err("%.8s: verify failed at file %s offset %llu, length %u"
			" (requested block: offset=%llu, length=%llu, flags=%x)\n",
			vc->name, vc->io_u->file->file_name, offset, len,
			vc->io_u->verify_offset, vc->io_u->buflen, vc->io_u->flags);

	if (vc->good_crc && vc->bad_crc) {
		log_err("       Expected CRC: ");
		hexdump(vc->good_crc, vc->crc_len);
		log_err("       Received CRC: ");
		hexdump(vc->bad_crc, vc->crc_len);
	}

	dump_verify_buffers(hdr, vc);
}

/*
 * Return data area 'header_num'
 */
static inline void *io_u_verify_off(struct verify_header *hdr, struct vcont *vc)
{
	return vc->io_u->buf + vc->hdr_num * hdr->len + hdr_size(vc->td, hdr);
}

static int check_pattern(char *buf, unsigned int len, unsigned int mod,
		unsigned int pattern_size, char *pattern, unsigned int header_size)
{
	unsigned int i;
	int rc;

	rc = cmp_pattern(pattern, pattern_size, mod, buf, len);
	if (!rc)
		goto done;

	/* Slow path, compare each byte */
	for (i = 0; i < len; i++) {
		if (buf[i] != pattern[mod]) {
			unsigned int bits;

			bits = hweight8(buf[i] ^ pattern[mod]);
			log_err("fio: got pattern '%02x', wanted '%02x'. Bad bits %d\n",
				(unsigned char)buf[i],
				(unsigned char)pattern[mod],
				bits);
			log_err("fio: bad pattern block offset %u\n",
				i + header_size);
			rc = EILSEQ;
			goto done;
		}
		mod++;
		if (mod == pattern_size)
			mod = 0;
	}

done:
	return rc;
}

/*
 *  The current thread will need its own buffer if there are multiple threads
 *  and the pattern contains the offset. Fio currently only has one pattern
 *  format specifier so we only need to check that one, but this may need to be
 *  changed if fio ever gains more pattern format specifiers.
 */
static inline bool pattern_need_buffer(struct thread_data *td)
{
	return (td->o.verify_async || td->o.use_thread) &&
		td->o.verify_fmt_sz &&
		td->o.verify_fmt[0].desc->paste == paste_blockoff;
}

static int verify_io_u_pattern(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	char *buf, *pattern;
	unsigned int header_size = __hdr_size(td->o.verify);
	unsigned int len, mod, pattern_size, pattern_interval_mod, bytes_done = 0, bytes_todo;
	int rc;
	unsigned long long offset = io_u->offset;

	pattern = td->o.verify_pattern;
	pattern_size = td->o.verify_pattern_bytes;
	assert(pattern_size != 0);

	/*
	 * Make this thread safe when verify_async is set and the verify
	 * pattern includes the offset.
	 */
	if (pattern_need_buffer(td)) {
		pattern = malloc(pattern_size);
		assert(pattern);
		memcpy(pattern, td->o.verify_pattern, pattern_size);
	}

	if (!td->o.verify_pattern_interval) {
		(void)paste_format_inplace(pattern, pattern_size,
					   td->o.verify_fmt, td->o.verify_fmt_sz, io_u);
	}

	/*
	 * We have 3 cases here:
	 * 1. Compare the entire buffer if (1) verify_interval is not set and
	 * (2) verify_pattern_interval is not set
	 * 2. Compare the entire *verify_interval* if (1) verify_interval *is*
	 * set and (2) verify_pattern_interval is not set
	 * 3. Compare *verify_pattern_interval* segments or subsets thereof if
	 * (2) verify_pattern_interval is set
	 */

	buf = (char *) hdr + header_size;
	len = get_hdr_inc(td, io_u) - header_size;
	if (td->o.verify_pattern_interval) {
		unsigned int extent = get_hdr_inc(td, io_u) * vc->hdr_num + header_size;
		pattern_interval_mod = extent % td->o.verify_pattern_interval;
		mod = pattern_interval_mod % pattern_size;
		bytes_todo = min(len, td->o.verify_pattern_interval - pattern_interval_mod);
		io_u->offset += extent / td->o.verify_pattern_interval * td->o.verify_pattern_interval;
	} else {
		mod = (get_hdr_inc(td, io_u) * vc->hdr_num + header_size) % pattern_size;
		bytes_todo = len;
		pattern_interval_mod = 0;
	}

	while (bytes_done < len) {
		if (td->o.verify_pattern_interval) {
			(void)paste_format_inplace(pattern, pattern_size,
					td->o.verify_fmt, td->o.verify_fmt_sz,
					io_u);
		}

		rc = check_pattern(buf, bytes_todo, mod, pattern_size, pattern, header_size);
		if (rc) {
			vc->name = "pattern";
			log_verify_failure(hdr, vc);
			break;
		}

		mod = 0;
		bytes_done += bytes_todo;
		buf += bytes_todo;
		io_u->offset += td->o.verify_pattern_interval;
		bytes_todo = min(len - bytes_done, td->o.verify_pattern_interval);
	}

	io_u->offset = offset;
	if (pattern_need_buffer(td))
		free(pattern);
	return rc;
}

static int verify_io_u_xxhash(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	uint32_t hash;
	void *state;

	dprint(FD_VERIFY, "xxhash verify io_u %p, len %u\n", vc->io_u, hdr->len);

	state = XXH32_init(1);
	XXH32_update(state, p, hdr->len - hdr_size(vc->td, hdr));
	hash = XXH32_digest(state);

	if (vh->hash == hash)
		return 0;

	vc->name = "xxhash";
	vc->good_crc = &vh->hash;
	vc->bad_crc = &hash;
	vc->crc_len = sizeof(hash);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha3(struct verify_header *hdr, struct vcont *vc,
			    struct fio_sha3_ctx *sha3_ctx, uint8_t *sha,
			    unsigned int sha_size, const char *name)
{
	void *p = io_u_verify_off(hdr, vc);

	dprint(FD_VERIFY, "%s verify io_u %p, len %u\n", name, vc->io_u, hdr->len);

	fio_sha3_update(sha3_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha3_final(sha3_ctx);

	if (!memcmp(sha, sha3_ctx->sha, sha_size))
		return 0;

	vc->name = name;
	vc->good_crc = sha;
	vc->bad_crc = sha3_ctx->sha;
	vc->crc_len = sha_size;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha3_224(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_224 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_224_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_224_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_224_DIGEST_SIZE, "sha3-224");
}

static int verify_io_u_sha3_256(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_256 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_256_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_256_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_256_DIGEST_SIZE, "sha3-256");
}

static int verify_io_u_sha3_384(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_384 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_384_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_384_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_384_DIGEST_SIZE, "sha3-384");
}

static int verify_io_u_sha3_512(struct verify_header *hdr, struct vcont *vc)
{
	struct vhdr_sha3_512 *vh = hdr_priv(hdr);
	uint8_t sha[SHA3_512_DIGEST_SIZE];
	struct fio_sha3_ctx sha3_ctx = {
		.sha = sha,
	};

	fio_sha3_512_init(&sha3_ctx);

	return verify_io_u_sha3(hdr, vc, &sha3_ctx, vh->sha,
				SHA3_512_DIGEST_SIZE, "sha3-512");
}

static int verify_io_u_sha512(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	uint8_t sha512[128];
	struct fio_sha512_ctx sha512_ctx = {
		.buf = sha512,
	};

	dprint(FD_VERIFY, "sha512 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha512_init(&sha512_ctx);
	fio_sha512_update(&sha512_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha512_final(&sha512_ctx);

	if (!memcmp(vh->sha512, sha512_ctx.buf, sizeof(sha512)))
		return 0;

	vc->name = "sha512";
	vc->good_crc = vh->sha512;
	vc->bad_crc = sha512_ctx.buf;
	vc->crc_len = sizeof(vh->sha512);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha256(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	uint8_t sha256[64];
	struct fio_sha256_ctx sha256_ctx = {
		.buf = sha256,
	};

	dprint(FD_VERIFY, "sha256 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha256_init(&sha256_ctx);
	fio_sha256_update(&sha256_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha256_final(&sha256_ctx);

	if (!memcmp(vh->sha256, sha256_ctx.buf, sizeof(sha256)))
		return 0;

	vc->name = "sha256";
	vc->good_crc = vh->sha256;
	vc->bad_crc = sha256_ctx.buf;
	vc->crc_len = sizeof(vh->sha256);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_sha1(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_sha1 *vh = hdr_priv(hdr);
	uint32_t sha1[5];
	struct fio_sha1_ctx sha1_ctx = {
		.H = sha1,
	};

	dprint(FD_VERIFY, "sha1 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_sha1_init(&sha1_ctx);
	fio_sha1_update(&sha1_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_sha1_final(&sha1_ctx);

	if (!memcmp(vh->sha1, sha1_ctx.H, sizeof(sha1)))
		return 0;

	vc->name = "sha1";
	vc->good_crc = vh->sha1;
	vc->bad_crc = sha1_ctx.H;
	vc->crc_len = sizeof(vh->sha1);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc7(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc7 *vh = hdr_priv(hdr);
	unsigned char c;

	dprint(FD_VERIFY, "crc7 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc7(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc7)
		return 0;

	vc->name = "crc7";
	vc->good_crc = &vh->crc7;
	vc->bad_crc = &c;
	vc->crc_len = 1;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc16(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc16 *vh = hdr_priv(hdr);
	unsigned short c;

	dprint(FD_VERIFY, "crc16 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc16(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc16)
		return 0;

	vc->name = "crc16";
	vc->good_crc = &vh->crc16;
	vc->bad_crc = &c;
	vc->crc_len = 2;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc64(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc64 *vh = hdr_priv(hdr);
	unsigned long long c;

	dprint(FD_VERIFY, "crc64 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc64(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc64)
		return 0;

	vc->name = "crc64";
	vc->good_crc = &vh->crc64;
	vc->bad_crc = &c;
	vc->crc_len = 8;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc32(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc32(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc32)
		return 0;

	vc->name = "crc32";
	vc->good_crc = &vh->crc32;
	vc->bad_crc = &c;
	vc->crc_len = 4;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_crc32c(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32c verify io_u %p, len %u\n", vc->io_u, hdr->len);

	c = fio_crc32c(p, hdr->len - hdr_size(vc->td, hdr));

	if (c == vh->crc32)
		return 0;

	vc->name = "crc32c";
	vc->good_crc = &vh->crc32;
	vc->bad_crc = &c;
	vc->crc_len = 4;
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

static int verify_io_u_md5(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_md5 *vh = hdr_priv(hdr);
	uint32_t hash[MD5_HASH_WORDS];
	struct fio_md5_ctx md5_ctx = {
		.hash = hash,
	};

	dprint(FD_VERIFY, "md5 verify io_u %p, len %u\n", vc->io_u, hdr->len);

	fio_md5_init(&md5_ctx);
	fio_md5_update(&md5_ctx, p, hdr->len - hdr_size(vc->td, hdr));
	fio_md5_final(&md5_ctx);

	if (!memcmp(vh->md5_digest, md5_ctx.hash, sizeof(hash)))
		return 0;

	vc->name = "md5";
	vc->good_crc = vh->md5_digest;
	vc->bad_crc = md5_ctx.hash;
	vc->crc_len = sizeof(hash);
	log_verify_failure(hdr, vc);
	return EILSEQ;
}

/*
 * Push IO verification to a separate thread
 */
int verify_io_u_async(struct thread_data *td, struct io_u **io_u_ptr)
{
	struct io_u *io_u = *io_u_ptr;

	pthread_mutex_lock(&td->io_u_lock);

	if (io_u->file)
		put_file_log(td, io_u->file);

	if (io_u->flags & IO_U_F_IN_CUR_DEPTH) {
		td->cur_depth--;
		io_u_clear(td, io_u, IO_U_F_IN_CUR_DEPTH);
	}
	flist_add_tail(&io_u->verify_list, &td->verify_list);
	*io_u_ptr = NULL;

	pthread_cond_signal(&td->verify_cond);
	pthread_mutex_unlock(&td->io_u_lock);
	return 0;
}

/*
 * Thanks Rusty, for spending the time so I don't have to.
 *
 * http://rusty.ozlabs.org/?p=560
 */
static int mem_is_zero(const void *data, size_t length)
{
	const unsigned char *p = data;
	size_t len;

	/* Check first 16 bytes manually */
	for (len = 0; len < 16; len++) {
		if (!length)
			return 1;
		if (*p)
			return 0;
		p++;
		length--;
	}

	/* Now we know that's zero, memcmp with self. */
	return memcmp(data, p, length) == 0;
}

static int mem_is_zero_slow(const void *data, size_t length, size_t *offset)
{
	const unsigned char *p = data;

	*offset = 0;
	while (length) {
		if (*p)
			break;
		(*offset)++;
		length--;
		p++;
	}

	return !length;
}

static int verify_trimmed_io_u(struct thread_data *td, struct io_u *io_u)
{
	size_t offset;

	if (!td->o.trim_zero)
		return 0;

	if (mem_is_zero(io_u->buf, io_u->buflen))
		return 0;

	mem_is_zero_slow(io_u->buf, io_u->buflen, &offset);

	log_err("trim: verify failed at file %s offset %llu, length %llu"
		", block offset %lu\n",
			io_u->file->file_name, io_u->verify_offset, io_u->buflen,
			(unsigned long) offset);
	return EILSEQ;
}

static int verify_header(struct io_u *io_u, struct thread_data *td,
			 struct verify_header *hdr, unsigned int hdr_num,
			 unsigned int hdr_len)
{
	void *p = hdr;
	uint32_t crc;

	if (hdr->magic != FIO_HDR_MAGIC) {
		log_err("verify: bad magic header %x, wanted %x",
			hdr->magic, FIO_HDR_MAGIC);
		goto err;
	}
	if (hdr->version != VERIFY_HEADER_VERSION) {
		log_err("verify: unsupported header version %x, wanted %x. Are you trying to verify across versions of fio?",
			hdr->version, VERIFY_HEADER_VERSION);
		goto err;
	}
	if (hdr->len != hdr_len) {
		log_err("verify: bad header length %u, wanted %u",
			hdr->len, hdr_len);
		goto err;
	}
	if (td->o.verify_header_seed && (hdr->rand_seed != io_u->rand_seed)) {
		log_err("verify: bad header rand_seed %"PRIu64
			", wanted %"PRIu64,
			hdr->rand_seed, io_u->rand_seed);
		goto err;
	}
	if (hdr->offset != io_u->verify_offset + hdr_num * td->o.verify_interval) {
		log_err("verify: bad header offset %"PRIu64
			", wanted %llu",
			hdr->offset, io_u->verify_offset);
		goto err;
	}

	/*
	 * For read-only workloads, the program cannot be certain of the
	 * last numberio written to a block. Checking of numberio will be
	 * done only for workloads that write data.  For verify_only or
	 * any mode de-selecting verify_write_sequence, numberio check is
	 * skipped.
	 */
	if (td_write(td) && (td_min_bs(td) == td_max_bs(td)) &&
	    !td->o.time_based)
		if (td->o.verify_write_sequence)
			if (hdr->numberio != io_u->numberio) {
				log_err("verify: bad header numberio %"PRIu64
					", wanted %"PRIu64,
					hdr->numberio, io_u->numberio);
				goto err;
			}

	crc = fio_crc32c(p, offsetof(struct verify_header, crc32));
	if (crc != hdr->crc32) {
		log_err("verify: bad header crc %x, calculated %x",
			hdr->crc32, crc);
		goto err;
	}
	return 0;

err:
	log_err(" at file %s offset %llu, length %u"
		" (requested block: offset=%llu, length=%llu)\n",
		io_u->file->file_name,
		io_u->verify_offset + hdr_num * hdr_len, hdr_len,
		io_u->verify_offset, io_u->buflen);

	if (td->o.verify_dump)
		dump_buf(p, hdr_len, io_u->verify_offset + hdr_num * hdr_len,
				"hdr_fail", io_u->file);

	return EILSEQ;
}

int verify_io_u(struct thread_data *td, struct io_u **io_u_ptr)
{
	struct verify_header *hdr;
	struct io_u *io_u = *io_u_ptr;
	unsigned int header_size, hdr_inc, hdr_num = 0;
	void *p;
	int ret;

	if (td->o.verify == VERIFY_NULL || io_u->ddir != DDIR_READ)
		return 0;
	/*
	 * If the IO engine is faking IO (like null), then just pretend
	 * we verified everything.
	 */
	if (td_ioengine_flagged(td, FIO_FAKEIO))
		return 0;

	/*
	 * If data has already been verified from the device, we can skip
	 * the actual verification phase here.
	 */
	if (io_u->flags & IO_U_F_VER_IN_DEV)
		return 0;

	if (io_u->flags & IO_U_F_TRIMMED) {
		ret = verify_trimmed_io_u(td, io_u);
		goto done;
	}

	hdr_inc = get_hdr_inc(td, io_u);

	ret = 0;
	for (p = io_u->buf; p < io_u->buf + io_u->buflen;
	     p += hdr_inc, hdr_num++) {
		struct vcont vc = {
			.io_u		= io_u,
			.hdr_num	= hdr_num,
			.td		= td,
		};
		unsigned int verify_type;

		if (ret && td->o.verify_fatal)
			break;

		header_size = __hdr_size(td->o.verify);
		if (td->o.verify_offset)
			memswp(p, p + td->o.verify_offset, header_size);
		hdr = p;

		if (td->o.verify != VERIFY_PATTERN_NO_HDR) {
			ret = verify_header(io_u, td, hdr, hdr_num, hdr_inc);
			if (ret)
				return ret;
		}

		if (td->o.verify != VERIFY_NONE)
			verify_type = td->o.verify;
		else
			verify_type = hdr->verify_type;

		switch (verify_type) {
		case VERIFY_HDR_ONLY:
			/* Header is always verified, check if pattern is left
			 * for verification. */
			if (td->o.verify_pattern_bytes)
				ret = verify_io_u_pattern(hdr, &vc);
			break;
		case VERIFY_MD5:
			ret = verify_io_u_md5(hdr, &vc);
			break;
		case VERIFY_CRC64:
			ret = verify_io_u_crc64(hdr, &vc);
			break;
		case VERIFY_CRC32C:
		case VERIFY_CRC32C_INTEL:
			ret = verify_io_u_crc32c(hdr, &vc);
			break;
		case VERIFY_CRC32:
			ret = verify_io_u_crc32(hdr, &vc);
			break;
		case VERIFY_CRC16:
			ret = verify_io_u_crc16(hdr, &vc);
			break;
		case VERIFY_CRC7:
			ret = verify_io_u_crc7(hdr, &vc);
			break;
		case VERIFY_SHA256:
			ret = verify_io_u_sha256(hdr, &vc);
			break;
		case VERIFY_SHA512:
			ret = verify_io_u_sha512(hdr, &vc);
			break;
		case VERIFY_SHA3_224:
			ret = verify_io_u_sha3_224(hdr, &vc);
			break;
		case VERIFY_SHA3_256:
			ret = verify_io_u_sha3_256(hdr, &vc);
			break;
		case VERIFY_SHA3_384:
			ret = verify_io_u_sha3_384(hdr, &vc);
			break;
		case VERIFY_SHA3_512:
			ret = verify_io_u_sha3_512(hdr, &vc);
			break;
		case VERIFY_XXHASH:
			ret = verify_io_u_xxhash(hdr, &vc);
			break;
		case VERIFY_SHA1:
			ret = verify_io_u_sha1(hdr, &vc);
			break;
		case VERIFY_PATTERN:
		case VERIFY_PATTERN_NO_HDR:
			ret = verify_io_u_pattern(hdr, &vc);
			break;
		default:
			log_err("Bad verify type %u\n", hdr->verify_type);
			ret = EINVAL;
		}

		if (ret && verify_type != hdr->verify_type && verify_type != VERIFY_PATTERN_NO_HDR)
			log_err("fio: verify type mismatch (%u media, %u given)\n",
					hdr->verify_type, verify_type);
	}

done:
	if (ret && td->o.verify_fatal)
		fio_mark_td_terminate(td);

	return ret;
}

static void fill_xxhash(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	void *state;

	state = XXH32_init(1);
	XXH32_update(state, p, len);
	vh->hash = XXH32_digest(state);
}

static void fill_sha3(struct fio_sha3_ctx *sha3_ctx, void *p, unsigned int len)
{
	fio_sha3_update(sha3_ctx, p, len);
	fio_sha3_final(sha3_ctx);
}

static void fill_sha3_224(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_224 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_224_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_256 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_256_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_384(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_384 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_384_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha3_512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha3_512 *vh = hdr_priv(hdr);
	struct fio_sha3_ctx sha3_ctx = {
		.sha = vh->sha,
	};

	fio_sha3_512_init(&sha3_ctx);
	fill_sha3(&sha3_ctx, p, len);
}

static void fill_sha512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	struct fio_sha512_ctx sha512_ctx = {
		.buf = vh->sha512,
	};

	fio_sha512_init(&sha512_ctx);
	fio_sha512_update(&sha512_ctx, p, len);
	fio_sha512_final(&sha512_ctx);
}

static void fill_sha256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	struct fio_sha256_ctx sha256_ctx = {
		.buf = vh->sha256,
	};

	fio_sha256_init(&sha256_ctx);
	fio_sha256_update(&sha256_ctx, p, len);
	fio_sha256_final(&sha256_ctx);
}

static void fill_sha1(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha1 *vh = hdr_priv(hdr);
	struct fio_sha1_ctx sha1_ctx = {
		.H = vh->sha1,
	};

	fio_sha1_init(&sha1_ctx);
	fio_sha1_update(&sha1_ctx, p, len);
	fio_sha1_final(&sha1_ctx);
}

static void fill_crc7(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc7 *vh = hdr_priv(hdr);

	vh->crc7 = fio_crc7(p, len);
}

static void fill_crc16(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc16 *vh = hdr_priv(hdr);

	vh->crc16 = fio_crc16(p, len);
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	vh->crc32 = fio_crc32(p, len);
}

static void fill_crc32c(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	vh->crc32 = fio_crc32c(p, len);
}

static void fill_crc64(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc64 *vh = hdr_priv(hdr);

	vh->crc64 = fio_crc64(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_md5 *vh = hdr_priv(hdr);
	struct fio_md5_ctx md5_ctx = {
		.hash = (uint32_t *) vh->md5_digest,
	};

	fio_md5_init(&md5_ctx);
	fio_md5_update(&md5_ctx, p, len);
	fio_md5_final(&md5_ctx);
}

static void __fill_hdr(struct thread_data *td, struct io_u *io_u,
		       struct verify_header *hdr, unsigned int header_num,
		       unsigned int header_len, uint64_t rand_seed)
{
	void *p = hdr;

	hdr->magic = FIO_HDR_MAGIC;
	hdr->version = VERIFY_HEADER_VERSION;
	hdr->verify_type = td->o.verify;
	hdr->len = header_len;
	hdr->rand_seed = rand_seed;
	hdr->offset = io_u->verify_offset + header_num * td->o.verify_interval;
	hdr->time_sec = io_u->start_time.tv_sec;
	hdr->time_nsec = io_u->start_time.tv_nsec;
	hdr->thread = td->thread_number;
	hdr->numberio = io_u->numberio;
	hdr->crc32 = fio_crc32c(p, offsetof(struct verify_header, crc32));
}


static void fill_hdr(struct thread_data *td, struct io_u *io_u,
		     struct verify_header *hdr, unsigned int header_num,
		     unsigned int header_len, uint64_t rand_seed)
{
	if (td->o.verify != VERIFY_PATTERN_NO_HDR)
		__fill_hdr(td, io_u, hdr, header_num, header_len, rand_seed);
}

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len)
{
	unsigned int data_len;
	void *data;
	char *p;

	p = (char *) hdr;

	fill_hdr(td, io_u, hdr, header_num, header_len, io_u->rand_seed);

	if (header_len <= hdr_size(td, hdr)) {
		td_verror(td, EINVAL, "Blocksize too small");
		return;
	}
	data_len = header_len - hdr_size(td, hdr);

	data = p + hdr_size(td, hdr);
	switch (td->o.verify) {
	case VERIFY_MD5:
		dprint(FD_VERIFY, "fill md5 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_md5(hdr, data, data_len);
		break;
	case VERIFY_CRC64:
		dprint(FD_VERIFY, "fill crc64 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc64(hdr, data, data_len);
		break;
	case VERIFY_CRC32C:
	case VERIFY_CRC32C_INTEL:
		dprint(FD_VERIFY, "fill crc32c io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc32c(hdr, data, data_len);
		break;
	case VERIFY_CRC32:
		dprint(FD_VERIFY, "fill crc32 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc32(hdr, data, data_len);
		break;
	case VERIFY_CRC16:
		dprint(FD_VERIFY, "fill crc16 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc16(hdr, data, data_len);
		break;
	case VERIFY_CRC7:
		dprint(FD_VERIFY, "fill crc7 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_crc7(hdr, data, data_len);
		break;
	case VERIFY_SHA256:
		dprint(FD_VERIFY, "fill sha256 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha256(hdr, data, data_len);
		break;
	case VERIFY_SHA512:
		dprint(FD_VERIFY, "fill sha512 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha512(hdr, data, data_len);
		break;
	case VERIFY_SHA3_224:
		dprint(FD_VERIFY, "fill sha3-224 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_224(hdr, data, data_len);
		break;
	case VERIFY_SHA3_256:
		dprint(FD_VERIFY, "fill sha3-256 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_256(hdr, data, data_len);
		break;
	case VERIFY_SHA3_384:
		dprint(FD_VERIFY, "fill sha3-384 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_384(hdr, data, data_len);
		break;
	case VERIFY_SHA3_512:
		dprint(FD_VERIFY, "fill sha3-512 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha3_512(hdr, data, data_len);
		break;
	case VERIFY_XXHASH:
		dprint(FD_VERIFY, "fill xxhash io_u %p, len %u\n",
						io_u, hdr->len);
		fill_xxhash(hdr, data, data_len);
		break;
	case VERIFY_SHA1:
		dprint(FD_VERIFY, "fill sha1 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha1(hdr, data, data_len);
		break;
	case VERIFY_HDR_ONLY:
	case VERIFY_PATTERN:
	case VERIFY_PATTERN_NO_HDR:
		/* nothing to do here */
		break;
	default:
		log_err("fio: bad verify type: %d\n", td->o.verify);
		assert(0);
	}

	if (td->o.verify_offset && hdr_size(td, hdr))
		memswp(p, p + td->o.verify_offset, hdr_size(td, hdr));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * checksum of choice
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.verify == VERIFY_NULL)
		return;

	fill_pattern_headers(td, io_u, 0, 0);
}

int get_next_verify(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo = NULL;

	/*
	 * this io_u is from a requeue, we already filled the offsets
	 */
	if (io_u->file)
		return 0;

	if (!RB_EMPTY_ROOT(&td->io_hist_tree)) {
		struct fio_rb_node *n = rb_first(&td->io_hist_tree);

		ipo = rb_entry(n, struct io_piece, rb_node);

		/*
		 * Ensure that the associated IO has completed
		 */
		if (atomic_load_acquire(&ipo->flags) & IP_F_IN_FLIGHT)
			goto nothing;

		rb_erase(n, &td->io_hist_tree);
		assert(ipo->flags & IP_F_ONRB);
		ipo->flags &= ~IP_F_ONRB;
	} else if (!flist_empty(&td->io_hist_list)) {
		ipo = flist_first_entry(&td->io_hist_list, struct io_piece, list);

		/*
		 * Ensure that the associated IO has completed
		 */
		if (atomic_load_acquire(&ipo->flags) & IP_F_IN_FLIGHT)
			goto nothing;

		flist_del(&ipo->list);
		assert(ipo->flags & IP_F_ONLIST);
		ipo->flags &= ~IP_F_ONLIST;
	}

	if (ipo) {
		td->io_hist_len--;

		io_u->offset = ipo->offset;
		io_u->verify_offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->numberio = ipo->numberio;
		io_u->file = ipo->file;
		io_u_set(td, io_u, IO_U_F_VER_LIST);

		if (ipo->flags & IP_F_TRIMMED)
			io_u_set(td, io_u, IO_U_F_TRIMMED);

		if (!fio_file_open(io_u->file)) {
			int r = td_io_open_file(td, io_u->file);

			if (r) {
				dprint(FD_VERIFY, "failed file %s open\n",
						io_u->file->file_name);
				return 1;
			}
		}

		get_file(ipo->file);
		assert(fio_file_open(io_u->file));
		io_u->ddir = DDIR_READ;
		io_u->xfer_buf = io_u->buf;
		io_u->xfer_buflen = io_u->buflen;

		remove_trim_entry(td, ipo);
		free(ipo);
		dprint(FD_VERIFY, "get_next_verify: ret io_u %p\n", io_u);

		if (!td->o.verify_pattern_bytes) {
			io_u->rand_seed = __rand(&td->verify_state);
			if (sizeof(int) != sizeof(long *))
				io_u->rand_seed *= __rand(&td->verify_state);
		}
		return 0;
	}

nothing:
	dprint(FD_VERIFY, "get_next_verify: empty\n");
	return 1;
}

void fio_verify_init(struct thread_data *td)
{
	if (td->o.verify == VERIFY_CRC32C_INTEL ||
	    td->o.verify == VERIFY_CRC32C) {
		crc32c_arm64_probe();
		crc32c_intel_probe();
	}
}

static void *verify_async_thread(void *data)
{
	struct thread_data *td = data;
	struct io_u *io_u;
	int ret = 0;

	if (fio_option_is_set(&td->o, verify_cpumask) &&
	    fio_setaffinity(td->pid, td->o.verify_cpumask)) {
		log_err("fio: failed setting verify thread affinity\n");
		goto done;
	}

	do {
		FLIST_HEAD(list);

		read_barrier();
		if (td->verify_thread_exit)
			break;

		pthread_mutex_lock(&td->io_u_lock);

		while (flist_empty(&td->verify_list) &&
		       !td->verify_thread_exit) {
			ret = pthread_cond_wait(&td->verify_cond,
							&td->io_u_lock);
			if (ret) {
				break;
			}
		}

		flist_splice_init(&td->verify_list, &list);
		pthread_mutex_unlock(&td->io_u_lock);

		if (flist_empty(&list))
			continue;

		while (!flist_empty(&list)) {
			io_u = flist_first_entry(&list, struct io_u, verify_list);
			flist_del_init(&io_u->verify_list);

			io_u_set(td, io_u, IO_U_F_NO_FILE_PUT);
			ret = verify_io_u(td, &io_u);

			put_io_u(td, io_u);
			if (!ret)
				continue;
			if (td_non_fatal_error(td, ERROR_TYPE_VERIFY_BIT, ret)) {
				update_error_count(td, ret);
				td_clear_error(td);
				ret = 0;
			}
		}
	} while (!ret);

	if (ret) {
		td_verror(td, ret, "async_verify");
		if (td->o.verify_fatal)
			fio_mark_td_terminate(td);
	}

done:
	pthread_mutex_lock(&td->io_u_lock);
	td->nr_verify_threads--;
	pthread_cond_signal(&td->free_cond);
	pthread_mutex_unlock(&td->io_u_lock);

	return NULL;
}

int verify_async_init(struct thread_data *td)
{
	int i, ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 2 * PTHREAD_STACK_MIN);

	td->verify_thread_exit = 0;

	td->verify_threads = malloc(sizeof(pthread_t) * td->o.verify_async);
	for (i = 0; i < td->o.verify_async; i++) {
		ret = pthread_create(&td->verify_threads[i], &attr,
					verify_async_thread, td);
		if (ret) {
			log_err("fio: async verify creation failed: %s\n",
					strerror(ret));
			break;
		}
		ret = pthread_detach(td->verify_threads[i]);
		if (ret) {
			log_err("fio: async verify thread detach failed: %s\n",
					strerror(ret));
			break;
		}
		td->nr_verify_threads++;
	}

	pthread_attr_destroy(&attr);

	if (i != td->o.verify_async) {
		log_err("fio: only %d verify threads started, exiting\n", i);

		pthread_mutex_lock(&td->io_u_lock);
		td->verify_thread_exit = 1;
		pthread_cond_broadcast(&td->verify_cond);
		pthread_mutex_unlock(&td->io_u_lock);

		return 1;
	}

	return 0;
}

void verify_async_exit(struct thread_data *td)
{
	pthread_mutex_lock(&td->io_u_lock);
	td->verify_thread_exit = 1;
	pthread_cond_broadcast(&td->verify_cond);

	while (td->nr_verify_threads)
		pthread_cond_wait(&td->free_cond, &td->io_u_lock);

	pthread_mutex_unlock(&td->io_u_lock);
	free(td->verify_threads);
	td->verify_threads = NULL;
}

int paste_blockoff(char *buf, unsigned int len, void *priv)
{
	struct io_u *io = priv;
	unsigned long long off;

	typecheck(__typeof__(off), io->offset);
	off = cpu_to_le64((uint64_t)io->offset);
	len = min(len, (unsigned int)sizeof(off));
	memcpy(buf, &off, len);
	return 0;
}

struct all_io_list *get_all_io_list(int save_mask, size_t *sz)
{
	struct all_io_list *rep;
	size_t depth;
	void *next;
	int nr;

	compiletime_assert(sizeof(struct all_io_list) == 8, "all_io_list");

	/*
	 * Calculate reply space needed. We need one 'io_state' per thread,
	 * and the size will vary depending on depth.
	 */
	depth = 0;
	nr = 0;
	for_each_td(td) {
		if (save_mask != IO_LIST_ALL && (__td_index + 1) != save_mask)
			continue;
		td->stop_io = 1;
		td->flags |= TD_F_VSTATE_SAVED;
		depth += (td->o.iodepth * td->o.nr_files);
		nr++;
	} end_for_each();

	if (!nr)
		return NULL;

	*sz = sizeof(*rep);
	*sz += nr * sizeof(struct thread_io_list);
	*sz += depth * sizeof(struct inflight_write);
	rep = calloc(1, *sz);

	rep->threads = cpu_to_le64((uint64_t) nr);

	next = &rep->state[0];
	for_each_td(td) {
		struct thread_io_list *s = next;

		if (save_mask != IO_LIST_ALL && (__td_index + 1) != save_mask)
			continue;

		for (int i = 0; i < td->o.iodepth; i++)
			s->inflight[i].numberio = cpu_to_le64(atomic_load_acquire(&td->inflight_numberio[i]));

		s->depth = cpu_to_le32((uint32_t) td->o.iodepth);
		s->numberio = cpu_to_le64((uint64_t) atomic_load_acquire(&td->inflight_issued));
		s->index = cpu_to_le64((uint64_t) __td_index);
		if (td->random_state.use64) {
			s->rand.state64.s[0] = cpu_to_le64(td->random_state.state64.s1);
			s->rand.state64.s[1] = cpu_to_le64(td->random_state.state64.s2);
			s->rand.state64.s[2] = cpu_to_le64(td->random_state.state64.s3);
			s->rand.state64.s[3] = cpu_to_le64(td->random_state.state64.s4);
			s->rand.state64.s[4] = cpu_to_le64(td->random_state.state64.s5);
			s->rand.state64.s[5] = 0;
			s->rand.use64 = cpu_to_le64((uint64_t)1);
		} else {
			s->rand.state32.s[0] = cpu_to_le32(td->random_state.state32.s1);
			s->rand.state32.s[1] = cpu_to_le32(td->random_state.state32.s2);
			s->rand.state32.s[2] = cpu_to_le32(td->random_state.state32.s3);
			s->rand.state32.s[3] = 0;
			s->rand.use64 = 0;
		}
		snprintf((char *) s->name, sizeof(s->name), "%s", td->o.name);
		next = io_list_next(s);
	} end_for_each();

	return rep;
}

static int open_state_file(const char *name, const char *prefix, int num,
			   int for_write)
{
	char out[PATH_MAX];
	int flags;
	int fd;

	if (for_write)
		flags = O_CREAT | O_TRUNC | O_WRONLY | O_SYNC;
	else
		flags = O_RDONLY;

#ifdef _WIN32
	flags |= O_BINARY;
#endif

	verify_state_gen_name(out, sizeof(out), name, prefix, num);

	fd = open(out, flags, 0644);
	if (fd == -1) {
		perror("fio: open state file");
		log_err("fio: state file: %s (for_write=%d)\n", out, for_write);
		return -1;
	}

	return fd;
}

static int write_thread_list_state(struct thread_io_list *s,
				   const char *prefix)
{
	struct verify_state_hdr hdr;
	uint64_t crc;
	ssize_t ret;
	int fd;

	fd = open_state_file((const char *) s->name, prefix, s->index, 1);
	if (fd == -1)
		return 1;

	crc = fio_crc32c((void *)s, thread_io_list_sz(s));

	hdr.version = cpu_to_le64((uint64_t) VSTATE_HDR_VERSION);
	hdr.size = cpu_to_le64((uint64_t) thread_io_list_sz(s));
	hdr.crc = cpu_to_le64(crc);
	ret = write(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr))
		goto write_fail;

	ret = write(fd, s, thread_io_list_sz(s));
	if (ret != thread_io_list_sz(s)) {
write_fail:
		if (ret < 0)
			perror("fio: write state file");
		log_err("fio: failed to write state file\n");
		ret = 1;
	} else
		ret = 0;

	close(fd);
	return ret;
}

void __verify_save_state(struct all_io_list *state, const char *prefix)
{
	struct thread_io_list *s = &state->state[0];
	unsigned int i;

	for (i = 0; i < le64_to_cpu(state->threads); i++) {
		write_thread_list_state(s,  prefix);
		s = io_list_next(s);
	}
}

void verify_save_state(int mask)
{
	struct all_io_list *state;
	size_t sz;

	state = get_all_io_list(mask, &sz);
	if (state) {
		char prefix[PATH_MAX];

		if (aux_path)
			sprintf(prefix, "%s%clocal", aux_path, FIO_OS_PATH_SEPARATOR);
		else
			strcpy(prefix, "local");

		__verify_save_state(state, prefix);
		free(state);
	}
}

void verify_free_state(struct thread_data *td)
{
	if (td->vstate)
		free(td->vstate);
}

void verify_assign_state(struct thread_data *td, void *p)
{
	struct thread_io_list *s = p;
	int i;

	s->depth = le32_to_cpu(s->depth);
	s->numberio = le64_to_cpu(s->numberio);
	s->rand.use64 = le64_to_cpu(s->rand.use64);

	if (s->rand.use64) {
		for (i = 0; i < 6; i++)
			s->rand.state64.s[i] = le64_to_cpu(s->rand.state64.s[i]);
	} else {
		for (i = 0; i < 4; i++)
			s->rand.state32.s[i] = le32_to_cpu(s->rand.state32.s[i]);
	}

	for (i = 0; i < s->depth; i++) {
		s->inflight[i].numberio = le64_to_cpu(s->inflight[i].numberio);
		dprint(FD_VERIFY, "verify_assign_state numberio=%"PRIu64", inflight[%d]=%"PRIu64"\n", s->numberio, i, s->inflight[i].numberio);
	}

	td->vstate = p;
}

int verify_state_hdr(struct verify_state_hdr *hdr, struct thread_io_list *s)
{
	uint64_t crc;

	hdr->version = le64_to_cpu(hdr->version);
	hdr->size = le64_to_cpu(hdr->size);
	hdr->crc = le64_to_cpu(hdr->crc);

	if (hdr->version != VSTATE_HDR_VERSION)
		return 1;

	crc = fio_crc32c((void *)s, hdr->size);
	if (crc != hdr->crc)
		return 1;

	return 0;
}

int verify_load_state(struct thread_data *td, const char *prefix)
{
	struct verify_state_hdr hdr;
	void *s = NULL;
	uint64_t crc;
	ssize_t ret;
	int fd;

	if (!td->o.verify_state)
		return 0;

	fd = open_state_file(td->o.name, prefix, td->thread_number - 1, 0);
	if (fd == -1)
		return 1;

	ret = read(fd, &hdr, sizeof(hdr));
	if (ret != sizeof(hdr)) {
		if (ret < 0)
			td_verror(td, errno, "read verify state hdr");
		log_err("fio: failed reading verify state header\n");
		goto err;
	}

	hdr.version = le64_to_cpu(hdr.version);
	hdr.size = le64_to_cpu(hdr.size);
	hdr.crc = le64_to_cpu(hdr.crc);

	if (hdr.version != VSTATE_HDR_VERSION) {
		log_err("fio: unsupported (%d) version in verify state header\n",
				(unsigned int) hdr.version);
		goto err;
	}

	s = malloc(hdr.size);
	ret = read(fd, s, hdr.size);
	if (ret != hdr.size) {
		if (ret < 0)
			td_verror(td, errno, "read verify state");
		log_err("fio: failed reading verity state\n");
		goto err;
	}

	crc = fio_crc32c(s, hdr.size);
	if (crc != hdr.crc) {
		log_err("fio: verify state is corrupt\n");
		goto err;
	}

	close(fd);

	verify_assign_state(td, s);
	return 0;
err:
	if (s)
		free(s);
	close(fd);
	return 1;
}

/*
 * Use the loaded verify state to know when to stop doing verification
 */
int verify_state_should_stop(struct thread_data *td, uint64_t numberio)
{
	struct thread_io_list *s = td->vstate;
	int i;

	dprint(FD_VERIFY, "verify_state_should_stop numberio=%"PRIu64"\n", numberio);
	if (!s)
		return 0;

	/* If the current seq is lower than the max issued seq, check to make sure
	 * the write was not inflight.
	 */
	if (numberio < s->numberio) {
		for (i = 0; i < s->depth; i++) {
			if (s->inflight[i].numberio == numberio) {
				log_info("Stop verify because seq %"PRIu64" was an inflight write\n",
					numberio);
				return 1;
			}
		}
	} else {
		log_info("Stop verify because seq %"PRIu64" >= %"PRIu64"\n",
			numberio, s->numberio);
		return 1;
	}

	return 0;
}
