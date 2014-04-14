/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <libgen.h>

#include "fio.h"
#include "verify.h"
#include "trim.h"
#include "lib/rand.h"
#include "lib/hweight.h"

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

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len);

static void fill_pattern(struct thread_data *td, void *p, unsigned int len,
			 char *pattern, unsigned int pattern_bytes)
{
	switch (pattern_bytes) {
	case 0:
		assert(0);
		break;
	case 1:
		dprint(FD_VERIFY, "fill verify pattern b=0 len=%u\n", len);
		memset(p, pattern[0], len);
		break;
	default: {
		unsigned int i = 0, size = 0;
		unsigned char *b = p;

		dprint(FD_VERIFY, "fill verify pattern b=%d len=%u\n",
					pattern_bytes, len);

		while (i < len) {
			size = pattern_bytes;
			if (size > (len - i))
				size = len - i;
			memcpy(b+i, pattern, size);
			i += size;
		}
		break;
		}
	}
}

void fill_buffer_pattern(struct thread_data *td, void *p, unsigned int len)
{
	fill_pattern(td, p, len, td->o.buffer_pattern, td->o.buffer_pattern_bytes);
}

void fill_verify_pattern(struct thread_data *td, void *p, unsigned int len,
			 struct io_u *io_u, unsigned long seed, int use_seed)
{
	if (!td->o.verify_pattern_bytes) {
		dprint(FD_VERIFY, "fill random bytes len=%u\n", len);

		if (use_seed)
			__fill_random_buf(p, len, seed);
		else
			io_u->rand_seed = fill_random_buf(&td->__verify_state, p, len);
		return;
	}

	if (io_u->buf_filled_len >= len) {
		dprint(FD_VERIFY, "using already filled verify pattern b=%d len=%u\n",
			td->o.verify_pattern_bytes, len);
		return;
	}

	fill_pattern(td, p, len, td->o.verify_pattern, td->o.verify_pattern_bytes);

	io_u->buf_filled_len = len;
}

static unsigned int get_hdr_inc(struct thread_data *td, struct io_u *io_u)
{
	unsigned int hdr_inc;

	hdr_inc = io_u->buflen;
	if (td->o.verify_interval && td->o.verify_interval <= io_u->buflen)
		hdr_inc = td->o.verify_interval;

	return hdr_inc;
}

static void fill_pattern_headers(struct thread_data *td, struct io_u *io_u,
				 unsigned long seed, int use_seed)
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
	case VERIFY_NULL:
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
	case VERIFY_XXHASH:
		len = sizeof(struct vhdr_xxhash);
		break;
	case VERIFY_META:
		len = sizeof(struct vhdr_meta);
		break;
	case VERIFY_SHA1:
		len = sizeof(struct vhdr_sha1);
		break;
	case VERIFY_PATTERN:
		len = 0;
		break;
	default:
		log_err("fio: unknown verify header!\n");
		assert(0);
	}

	return len + sizeof(struct verify_header);
}

static inline unsigned int hdr_size(struct verify_header *hdr)
{
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
static int dump_buf_warned;

static void dump_buf(char *buf, unsigned int len, unsigned long long offset,
		     const char *type, struct fio_file *f)
{
	char *ptr, fname[DUMP_BUF_SZ];
	size_t buf_left = DUMP_BUF_SZ;
	int ret, fd;

	ptr = strdup(f->file_name);

	fname[DUMP_BUF_SZ - 1] = '\0';
	strncpy(fname, basename(ptr), DUMP_BUF_SZ - 1);

	buf_left -= strlen(fname);
	if (buf_left <= 0) {
		if (!dump_buf_warned) {
			log_err("fio: verify failure dump buffer too small\n");
			dump_buf_warned = 1;
		}
		free(ptr);
		return;
	}

	snprintf(fname + strlen(fname), buf_left, ".%llu.%s", offset, type);

	fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
	if (fd < 0) {
		perror("open verify buf file");
		return;
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
	free(ptr);
}

/*
 * Dump the contents of the read block and re-generate the correct data
 * and dump that too.
 */
static void dump_verify_buffers(struct verify_header *hdr, struct vcont *vc)
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

	dump_buf(io_u->buf + hdr_offset, hdr->len, io_u->offset + hdr_offset,
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

	dump_buf(buf + hdr_offset, hdr->len, io_u->offset + hdr_offset,
			"expected", vc->io_u->file);
	free(buf);
}

static void log_verify_failure(struct verify_header *hdr, struct vcont *vc)
{
	unsigned long long offset;

	offset = vc->io_u->offset;
	offset += vc->hdr_num * hdr->len;
	log_err("%.8s: verify failed at file %s offset %llu, length %u\n",
			vc->name, vc->io_u->file->file_name, offset, hdr->len);

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
	return vc->io_u->buf + vc->hdr_num * hdr->len + hdr_size(hdr);
}

static int verify_io_u_pattern(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct io_u *io_u = vc->io_u;
	char *buf, *pattern;
	unsigned int header_size = __hdr_size(td->o.verify);
	unsigned int len, mod, i, size, pattern_size;

	pattern = td->o.verify_pattern;
	pattern_size = td->o.verify_pattern_bytes;
	if (pattern_size <= 1)
		pattern_size = MAX_PATTERN_SIZE;
	buf = (void *) hdr + header_size;
	len = get_hdr_inc(td, io_u) - header_size;
	mod = header_size % pattern_size;

	for (i = 0; i < len; i += size) {
		size = pattern_size - mod;
		if (size > (len - i))
			size = len - i;
		if (memcmp(buf + i, pattern + mod, size))
			/* Let the slow compare find the first mismatch byte. */
			break;
		mod = 0;
	}

	for (; i < len; i++) {
		if (buf[i] != pattern[mod]) {
			unsigned int bits;

			bits = hweight8(buf[i] ^ pattern[mod]);
			log_err("fio: got pattern %x, wanted %x. Bad bits %d\n",
				buf[i], pattern[mod], bits);
			log_err("fio: bad pattern block offset %u\n", i);
			dump_verify_buffers(hdr, vc);
			return EILSEQ;
		}
		mod++;
		if (mod == td->o.verify_pattern_bytes)
			mod = 0;
	}

	return 0;
}

static int verify_io_u_meta(struct verify_header *hdr, struct vcont *vc)
{
	struct thread_data *td = vc->td;
	struct vhdr_meta *vh = hdr_priv(hdr);
	struct io_u *io_u = vc->io_u;
	int ret = EILSEQ;

	dprint(FD_VERIFY, "meta verify io_u %p, len %u\n", io_u, hdr->len);

	if (vh->offset == io_u->offset + vc->hdr_num * td->o.verify_interval)
		ret = 0;

	if (td->o.verify_pattern_bytes)
		ret |= verify_io_u_pattern(hdr, vc);

	/*
	 * For read-only workloads, the program cannot be certain of the
	 * last numberio written to a block. Checking of numberio will be done
	 * only for workloads that write data.
	 * For verify_only, numberio will be checked in the last iteration when
	 * the correct state of numberio, that would have been written to each
	 * block in a previous run of fio, has been reached.
	 */
	if (td_write(td) || td_rw(td))
		if (!td->o.verify_only || td->o.loops == 0)
			if (vh->numberio != io_u->numberio)
				ret = EILSEQ;

	if (!ret)
		return 0;

	vc->name = "meta";
	log_verify_failure(hdr, vc);
	return ret;
}

static int verify_io_u_xxhash(struct verify_header *hdr, struct vcont *vc)
{
	void *p = io_u_verify_off(hdr, vc);
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	uint32_t hash;
	void *state;

	dprint(FD_VERIFY, "xxhash verify io_u %p, len %u\n", vc->io_u, hdr->len);

	state = XXH32_init(1);
	XXH32_update(state, p, hdr->len - hdr_size(hdr));
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
	fio_sha512_update(&sha512_ctx, p, hdr->len - hdr_size(hdr));

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
	fio_sha256_update(&sha256_ctx, p, hdr->len - hdr_size(hdr));

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
	fio_sha1_update(&sha1_ctx, p, hdr->len - hdr_size(hdr));

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

	c = fio_crc7(p, hdr->len - hdr_size(hdr));

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

	c = fio_crc16(p, hdr->len - hdr_size(hdr));

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

	c = fio_crc64(p, hdr->len - hdr_size(hdr));

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

	c = fio_crc32(p, hdr->len - hdr_size(hdr));

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

	c = fio_crc32c(p, hdr->len - hdr_size(hdr));

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
	fio_md5_update(&md5_ctx, p, hdr->len - hdr_size(hdr));

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
int verify_io_u_async(struct thread_data *td, struct io_u *io_u)
{
	if (io_u->file)
		put_file_log(td, io_u->file);

	pthread_mutex_lock(&td->io_u_lock);

	if (io_u->flags & IO_U_F_IN_CUR_DEPTH) {
		td->cur_depth--;
		io_u->flags &= ~IO_U_F_IN_CUR_DEPTH;
	}
	flist_add_tail(&io_u->verify_list, &td->verify_list);
	io_u->flags |= IO_U_F_FREE_DEF;
	pthread_mutex_unlock(&td->io_u_lock);

	pthread_cond_signal(&td->verify_cond);
	return 0;
}

static int verify_trimmed_io_u(struct thread_data *td, struct io_u *io_u)
{
	static char zero_buf[1024];
	unsigned int this_len, len;
	int ret = 0;
	void *p;

	if (!td->o.trim_zero)
		return 0;

	len = io_u->buflen;
	p = io_u->buf;
	do {
		this_len = sizeof(zero_buf);
		if (this_len > len)
			this_len = len;
		if (memcmp(p, zero_buf, this_len)) {
			ret = EILSEQ;
			break;
		}
		len -= this_len;
		p += this_len;
	} while (len);

	if (!ret)
		return 0;

	log_err("trim: verify failed at file %s offset %llu, length %lu"
		", block offset %lu\n",
			io_u->file->file_name, io_u->offset, io_u->buflen,
			(unsigned long) (p - io_u->buf));
	return ret;
}

static int verify_header(struct io_u *io_u, struct verify_header *hdr)
{
	void *p = hdr;
	uint32_t crc;

	if (hdr->magic != FIO_HDR_MAGIC)
		return 1;
	if (hdr->len > io_u->buflen)
		return 2;
	if (hdr->rand_seed != io_u->rand_seed)
		return 3;

	crc = fio_crc32c(p, offsetof(struct verify_header, crc32));
	if (crc == hdr->crc32)
		return 0;
	log_err("fio: verify header crc %x, calculated %x\n", hdr->crc32, crc);
	return 4;
}

int verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	struct verify_header *hdr;
	unsigned int header_size, hdr_inc, hdr_num = 0;
	void *p;
	int ret;

	if (td->o.verify == VERIFY_NULL || io_u->ddir != DDIR_READ)
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

		/*
		 * Make rand_seed check pass when have verifysort or
		 * verify_backlog.
		 */
		if (td->o.verifysort || (td->flags & TD_F_VER_BACKLOG))
			io_u->rand_seed = hdr->rand_seed;

		ret = verify_header(io_u, hdr);
		switch (ret) {
		case 0:
			break;
		case 1:
			log_err("verify: bad magic header %x, wanted %x at "
				"file %s offset %llu, length %u\n",
				hdr->magic, FIO_HDR_MAGIC,
				io_u->file->file_name,
				io_u->offset + hdr_num * hdr->len, hdr->len);
			return EILSEQ;
			break;
		case 2:
			log_err("fio: verify header exceeds buffer length (%u "
				"> %lu)\n", hdr->len, io_u->buflen);
			return EILSEQ;
			break;
		case 3:
			log_err("verify: bad header rand_seed %"PRIu64
				", wanted %"PRIu64" at file %s offset %llu, "
				"length %u\n",
				hdr->rand_seed, io_u->rand_seed,
				io_u->file->file_name,
				io_u->offset + hdr_num * hdr->len, hdr->len);
			return EILSEQ;
			break;
		case 4:
			return EILSEQ;
			break;
		default:
			log_err("verify: unknown header error at file %s "
			"offset %llu, length %u\n",
			io_u->file->file_name,
			io_u->offset + hdr_num * hdr->len, hdr->len);
			return EILSEQ;
		}

		if (td->o.verify != VERIFY_NONE)
			verify_type = td->o.verify;
		else
			verify_type = hdr->verify_type;

		switch (verify_type) {
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
		case VERIFY_XXHASH:
			ret = verify_io_u_xxhash(hdr, &vc);
			break;
		case VERIFY_META:
			ret = verify_io_u_meta(hdr, &vc);
			break;
		case VERIFY_SHA1:
			ret = verify_io_u_sha1(hdr, &vc);
			break;
		case VERIFY_PATTERN:
			ret = verify_io_u_pattern(hdr, &vc);
			break;
		default:
			log_err("Bad verify type %u\n", hdr->verify_type);
			ret = EINVAL;
		}

		if (ret && verify_type != hdr->verify_type)
			log_err("fio: verify type mismatch (%u media, %u given)\n",
					hdr->verify_type, verify_type);
	}

done:
	if (ret && td->o.verify_fatal)
		td->terminate = 1;

	return ret;
}

static void fill_meta(struct verify_header *hdr, struct thread_data *td,
		      struct io_u *io_u, unsigned int header_num)
{
	struct vhdr_meta *vh = hdr_priv(hdr);

	vh->thread = td->thread_number;

	vh->time_sec = io_u->start_time.tv_sec;
	vh->time_usec = io_u->start_time.tv_usec;

	vh->numberio = io_u->numberio;

	vh->offset = io_u->offset + header_num * td->o.verify_interval;
}

static void fill_xxhash(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_xxhash *vh = hdr_priv(hdr);
	void *state;

	state = XXH32_init(1);
	XXH32_update(state, p, len);
	vh->hash = XXH32_digest(state);
}

static void fill_sha512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	struct fio_sha512_ctx sha512_ctx = {
		.buf = vh->sha512,
	};

	fio_sha512_init(&sha512_ctx);
	fio_sha512_update(&sha512_ctx, p, len);
}

static void fill_sha256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	struct fio_sha256_ctx sha256_ctx = {
		.buf = vh->sha256,
	};

	fio_sha256_init(&sha256_ctx);
	fio_sha256_update(&sha256_ctx, p, len);
}

static void fill_sha1(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha1 *vh = hdr_priv(hdr);
	struct fio_sha1_ctx sha1_ctx = {
		.H = vh->sha1,
	};

	fio_sha1_init(&sha1_ctx);
	fio_sha1_update(&sha1_ctx, p, len);
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
}

static void populate_hdr(struct thread_data *td, struct io_u *io_u,
			 struct verify_header *hdr, unsigned int header_num,
			 unsigned int header_len)
{
	unsigned int data_len;
	void *data, *p;

	p = (void *) hdr;

	hdr->magic = FIO_HDR_MAGIC;
	hdr->verify_type = td->o.verify;
	hdr->len = header_len;
	hdr->rand_seed = io_u->rand_seed;
	hdr->crc32 = fio_crc32c(p, offsetof(struct verify_header, crc32));

	data_len = header_len - hdr_size(hdr);

	data = p + hdr_size(hdr);
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
	case VERIFY_XXHASH:
		dprint(FD_VERIFY, "fill xxhash io_u %p, len %u\n",
						io_u, hdr->len);
		fill_xxhash(hdr, data, data_len);
		break;
	case VERIFY_META:
		dprint(FD_VERIFY, "fill meta io_u %p, len %u\n",
						io_u, hdr->len);
		fill_meta(hdr, td, io_u, header_num);
		break;
	case VERIFY_SHA1:
		dprint(FD_VERIFY, "fill sha1 io_u %p, len %u\n",
						io_u, hdr->len);
		fill_sha1(hdr, data, data_len);
		break;
	case VERIFY_PATTERN:
		/* nothing to do here */
		break;
	default:
		log_err("fio: bad verify type: %d\n", td->o.verify);
		assert(0);
	}
	if (td->o.verify_offset)
		memswp(p, p + td->o.verify_offset, hdr_size(hdr));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * checksum of choice
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	if (td->o.verify == VERIFY_NULL)
		return;

	io_u->numberio = td->io_issues[io_u->ddir];

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
		struct rb_node *n = rb_first(&td->io_hist_tree);

		ipo = rb_entry(n, struct io_piece, rb_node);

		/*
		 * Ensure that the associated IO has completed
		 */
		read_barrier();
		if (ipo->flags & IP_F_IN_FLIGHT)
			goto nothing;

		rb_erase(n, &td->io_hist_tree);
		assert(ipo->flags & IP_F_ONRB);
		ipo->flags &= ~IP_F_ONRB;
	} else if (!flist_empty(&td->io_hist_list)) {
		ipo = flist_entry(td->io_hist_list.next, struct io_piece, list);

		/*
		 * Ensure that the associated IO has completed
		 */
		read_barrier();
		if (ipo->flags & IP_F_IN_FLIGHT)
			goto nothing;

		flist_del(&ipo->list);
		assert(ipo->flags & IP_F_ONLIST);
		ipo->flags &= ~IP_F_ONLIST;
	}

	if (ipo) {
		td->io_hist_len--;

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->numberio = ipo->numberio;
		io_u->file = ipo->file;
		io_u->flags |= IO_U_F_VER_LIST;

		if (ipo->flags & IP_F_TRIMMED)
			io_u->flags |= IO_U_F_TRIMMED;

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
			io_u->rand_seed = __rand(&td->__verify_state);
			if (sizeof(int) != sizeof(long *))
				io_u->rand_seed *= __rand(&td->__verify_state);
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
		crc32c_intel_probe();
	}
}

static void *verify_async_thread(void *data)
{
	struct thread_data *td = data;
	struct io_u *io_u;
	int ret = 0;

	if (td->o.verify_cpumask_set &&
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
				pthread_mutex_unlock(&td->io_u_lock);
				break;
			}
		}

		flist_splice_init(&td->verify_list, &list);
		pthread_mutex_unlock(&td->io_u_lock);

		if (flist_empty(&list))
			continue;

		while (!flist_empty(&list)) {
			io_u = flist_entry(list.next, struct io_u, verify_list);
			flist_del(&io_u->verify_list);

			ret = verify_io_u(td, io_u);
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
			td->terminate = 1;
	}

done:
	pthread_mutex_lock(&td->io_u_lock);
	td->nr_verify_threads--;
	pthread_mutex_unlock(&td->io_u_lock);

	pthread_cond_signal(&td->free_cond);
	return NULL;
}

int verify_async_init(struct thread_data *td)
{
	int i, ret;
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN);

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
		td->verify_thread_exit = 1;
		write_barrier();
		pthread_cond_broadcast(&td->verify_cond);
		return 1;
	}

	return 0;
}

void verify_async_exit(struct thread_data *td)
{
	td->verify_thread_exit = 1;
	write_barrier();
	pthread_cond_broadcast(&td->verify_cond);

	pthread_mutex_lock(&td->io_u_lock);

	while (td->nr_verify_threads)
		pthread_cond_wait(&td->free_cond, &td->io_u_lock);

	pthread_mutex_unlock(&td->io_u_lock);
	free(td->verify_threads);
	td->verify_threads = NULL;
}
