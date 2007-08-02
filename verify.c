/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>

#include "fio.h"

#include "crc/md5.h"
#include "crc/crc64.h"
#include "crc/crc32.h"
#include "crc/crc16.h"
#include "crc/crc7.h"
#include "crc/sha256.h"
#include "crc/sha512.h"

static void fill_random_bytes(struct thread_data *td, void *p, unsigned int len)
{
	unsigned int todo;
	int r;

	while (len) {
		r = os_random_long(&td->verify_state);

		/*
		 * lrand48_r seems to be broken and only fill the bottom
		 * 32-bits, even on 64-bit archs with 64-bit longs
		 */
		todo = sizeof(r);
		if (todo > len)
			todo = len;

		memcpy(p, &r, todo);

		len -= todo;
		p += todo;
	}
}

static void fill_pattern(struct thread_data *td, void *p, unsigned int len)
{
	switch (td->o.verify_pattern_bytes) {
	case 0:
		fill_random_bytes(td, p, len);
		break;
	case 1:
		memset(p, td->o.verify_pattern, len);
		break;
	case 2:
	case 3:
	case 4: {
		unsigned int pattern = td->o.verify_pattern;
		unsigned int i = 0;
		unsigned char c1, c2, c3, c4;
		unsigned char *b = p;

		c1 = pattern & 0xff;
		pattern >>= 8;
		c2 = pattern & 0xff;
		pattern >>= 8;
		c3 = pattern & 0xff;
		pattern >>= 8;
		c4 = pattern & 0xff;

		while (i < len) {
			b[i++] = c1;
			if (i == len)
				break;
			b[i++] = c2;
			if (td->o.verify_pattern_bytes == 2 || i == len)
				continue;
			b[i++] = c3;
			if (td->o.verify_pattern_bytes == 3 || i == len)
				continue;
			b[i++] = c4;
		}
		break;
		}
	}
}

static void memswp(void* buf1, void* buf2, unsigned int len)
{
	struct verify_header swap;

	memcpy(&swap, buf1, len);
	memcpy(buf1, buf2, len);
	memcpy(buf2, &swap, len);
}

static void hexdump(void *buffer, int len)
{
	unsigned char *p = buffer;
	int i;

	for (i = 0; i < len; i++)
		log_info("%02x", p[i]);
	log_info("\n");
}

/*
 * Prepare for seperation of verify_header and checksum header
 */
static inline unsigned int __hdr_size(int verify_type)
{
	unsigned int len;

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
	case VERIFY_CRC32:
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
	case VERIFY_META:
		len = sizeof(struct vhdr_meta);
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
 * Return data area 'header_num'
 */
static inline void *io_u_verify_off(struct verify_header *hdr,
				    struct io_u *io_u,
				    unsigned char header_num)
{
	return io_u->buf + header_num * hdr->len + hdr_size(hdr);
}

static int verify_io_u_meta(struct verify_header *hdr, struct thread_data *td,
                            struct io_u *io_u, unsigned int header_num)
{
	struct vhdr_meta *vh = hdr_priv(hdr);

	if (vh->offset != io_u->offset + header_num * td->o.verify_interval) {
		log_err("meta: verify failed at %llu/%u\n",
		              io_u->offset + header_num * hdr->len,
		              hdr->len);
		return 1;
	}

	return 0;
}

static int verify_io_u_sha512(struct verify_header *hdr, struct io_u *io_u,
			      unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	uint8_t sha512[128];
	struct sha512_ctx sha512_ctx = {
		.buf = sha512,
	};

	sha512_init(&sha512_ctx);
	sha512_update(&sha512_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->sha512, sha512_ctx.buf, sizeof(sha512))) {
		log_err("sha512: verify failed at %llu/%u\n",
		              io_u->offset + header_num * hdr->len,
		              hdr->len);
		hexdump(vh->sha512, sizeof(vh->sha512));
		hexdump(sha512_ctx.buf, sizeof(sha512));
		return 1;
	}

	return 0;
}

static int verify_io_u_sha256(struct verify_header *hdr, struct io_u *io_u,
			      unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	uint8_t sha256[128];
	struct sha256_ctx sha256_ctx = {
		.buf = sha256,
	};

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->sha256, sha256_ctx.buf, sizeof(sha256))) {
		log_err("sha256: verify failed at %llu/%u\n",
		              io_u->offset + header_num * hdr->len,
		              hdr->len);
		hexdump(vh->sha256, sizeof(vh->sha256));
		hexdump(sha256_ctx.buf, sizeof(sha256));
		return 1;
	}

	return 0;
}

static int verify_io_u_crc7(struct verify_header *hdr, struct io_u *io_u,
                            unsigned char header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc7 *vh = hdr_priv(hdr);
	unsigned char c;

	c = crc7(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc7) {
		log_err("crc7: verify failed at %llu/%u\n",
		                io_u->offset + header_num * hdr->len,
				hdr->len);
		log_err("crc7: wanted %x, got %x\n", vh->crc7, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_crc16(struct verify_header *hdr, struct io_u *io_u,
                             unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc16 *vh = hdr_priv(hdr);
	unsigned short c;

	c = crc16(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc16) {
		log_err("crc16: verify failed at %llu/%u\n",
		                io_u->offset + header_num * hdr->len,
				hdr->len);
		log_err("crc16: wanted %x, got %x\n", vh->crc16, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_crc64(struct verify_header *hdr, struct io_u *io_u,
                             unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc64 *vh = hdr_priv(hdr);
	unsigned long long c;

	c = crc64(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc64) {
		log_err("crc64: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len,
				hdr->len);
		log_err("crc64: wanted %llx, got %llx\n", (unsigned long long) vh->crc64, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u,
		             unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	c = crc32(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc32) {
		log_err("crc32: verify failed at %llu/%u\n",
		                io_u->offset + header_num * hdr->len,
				hdr->len);
		log_err("crc32: wanted %x, got %x\n", vh->crc32, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_md5(struct verify_header *hdr, struct io_u *io_u,
		           unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_md5 *vh = hdr_priv(hdr);
	uint32_t hash[MD5_HASH_WORDS];
	struct md5_ctx md5_ctx = {
		.hash = hash,
	};

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->md5_digest, md5_ctx.hash, sizeof(hash))) {
		log_err("md5: verify failed at %llu/%u\n",
		              io_u->offset + header_num * hdr->len,
		              hdr->len);
		hexdump(vh->md5_digest, sizeof(vh->md5_digest));
		hexdump(md5_ctx.hash, sizeof(hash));
		return 1;
	}

	return 0;
}

int verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	struct verify_header *hdr;
	unsigned int hdr_inc, hdr_num = 0;
	void *p;
	int ret;

	if (td->o.verify == VERIFY_NULL || io_u->ddir != DDIR_READ)
		return 0;

	hdr_inc = io_u->buflen;
	if (td->o.verify_interval)
		hdr_inc = td->o.verify_interval;

	for (p = io_u->buf; p < io_u->buf + io_u->buflen; p += hdr_inc) {
		if (td->o.verify_offset)
			memswp(p, p + td->o.verify_offset, __hdr_size(td->o.verify));

		hdr = p;

		if (hdr->fio_magic != FIO_HDR_MAGIC) {
			log_err("Bad verify header %x\n", hdr->fio_magic);
			return EIO;
		}

		switch (hdr->verify_type) {
		case VERIFY_MD5:
			ret = verify_io_u_md5(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC64:
			ret = verify_io_u_crc64(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC32:
			ret = verify_io_u_crc32(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC16:
			ret = verify_io_u_crc16(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC7:
			ret = verify_io_u_crc7(hdr, io_u, hdr_num);
			break;
		case VERIFY_SHA256:
			ret = verify_io_u_sha256(hdr, io_u, hdr_num);
			break;
		case VERIFY_SHA512:
			ret = verify_io_u_sha512(hdr, io_u, hdr_num);
			break;
		case VERIFY_META:
			ret = verify_io_u_meta(hdr, td, io_u, hdr_num);
			break;
		default:
			log_err("Bad verify type %u\n", hdr->verify_type);
			ret = 1;
		}
		hdr_num++;
	}

	return 0;
}

static void fill_meta(struct verify_header *hdr, struct thread_data *td,
                      struct io_u *io_u, unsigned int header_num)
{
	struct vhdr_meta *vh = hdr_priv(hdr);

	vh->thread = td->thread_number;

	vh->time_sec = io_u->start_time.tv_sec;
	vh->time_usec = io_u->start_time.tv_usec;

	vh->numberio = td->io_issues[DDIR_WRITE];

	vh->offset = io_u->offset + header_num * td->o.verify_interval;
}

static void fill_sha512(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha512 *vh = hdr_priv(hdr);
	struct sha512_ctx sha512_ctx = {
		.buf = vh->sha512,
	};

	sha512_init(&sha512_ctx);
	sha512_update(&sha512_ctx, p, len);
}

static void fill_sha256(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_sha256 *vh = hdr_priv(hdr);
	struct sha256_ctx sha256_ctx = {
		.buf = vh->sha256,
	};

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, p, len);
}

static void fill_crc7(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc7 *vh = hdr_priv(hdr);

	vh->crc7 = crc7(p, len);
}

static void fill_crc16(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc16 *vh = hdr_priv(hdr);

	vh->crc16 = crc16(p, len);
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	vh->crc32 = crc32(p, len);
}

static void fill_crc64(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc64 *vh = hdr_priv(hdr);

	vh->crc64 = crc64(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_md5 *vh = hdr_priv(hdr);
	struct md5_ctx md5_ctx = {
		.hash = (uint32_t *) vh->md5_digest,
	};

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, p, len);
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * crc32 or md5 sum of that data.
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	struct verify_header *hdr;
	void *p = io_u->buf, *data;
	unsigned int hdr_inc, data_len, header_num = 0;

	if (td->o.verify == VERIFY_NULL)
		return;

	fill_pattern(td, p, io_u->buflen);

	hdr_inc = io_u->buflen;
	if (td->o.verify_interval)
		hdr_inc = td->o.verify_interval;

	for (;p < io_u->buf + io_u->buflen; p += hdr_inc) {
		hdr = p;

		hdr->fio_magic = FIO_HDR_MAGIC;
		hdr->verify_type = td->o.verify;
		hdr->len = hdr_inc;
		data_len = hdr_inc - hdr_size(hdr);

		data = p + hdr_size(hdr);
		switch (td->o.verify) {
		case VERIFY_MD5:
			fill_md5(hdr, data, data_len);
			break;
		case VERIFY_CRC64:
			fill_crc64(hdr, data, data_len);
			break;
		case VERIFY_CRC32:
			fill_crc32(hdr, data, data_len);
			break;
		case VERIFY_CRC16:
			fill_crc16(hdr, data, data_len);
			break;
		case VERIFY_CRC7:
			fill_crc7(hdr, data, data_len);
			break;
		case VERIFY_SHA256:
			fill_sha256(hdr, data, data_len);
			break;
		case VERIFY_SHA512:
			fill_sha512(hdr, data, data_len);
			break;
		case VERIFY_META:
			fill_meta(hdr, td, io_u, header_num);
			break;
		default:
			log_err("fio: bad verify type: %d\n", td->o.verify);
			assert(0);
		}
		if (td->o.verify_offset)
			memswp(p, p + td->o.verify_offset, hdr_size(hdr));
		header_num++;
	}
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
		rb_erase(n, &td->io_hist_tree);
	} else if (!list_empty(&td->io_hist_list)) {
		ipo = list_entry(td->io_hist_list.next, struct io_piece, list);
		list_del(&ipo->list);
	}

	if (ipo) {
		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->file = ipo->file;

		if ((io_u->file->flags & FIO_FILE_OPEN) == 0) {
			int r = td_io_open_file(td, io_u->file);

			if (r)
				return 1;
		}

		get_file(ipo->file);
		assert(io_u->file->flags & FIO_FILE_OPEN);
		io_u->ddir = DDIR_READ;
		io_u->xfer_buf = io_u->buf;
		io_u->xfer_buflen = io_u->buflen;
		free(ipo);
		return 0;
	}

	return 1;
}
