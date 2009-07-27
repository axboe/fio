/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "fio.h"
#include "verify.h"
#include "smalloc.h"

#include "crc/md5.h"
#include "crc/crc64.h"
#include "crc/crc32.h"
#include "crc/crc32c.h"
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
		dprint(FD_VERIFY, "fill random bytes len=%u\n", len);
		fill_random_bytes(td, p, len);
		break;
	case 1:
		dprint(FD_VERIFY, "fill verify pattern b=0 len=%u\n", len);
		memset(p, td->o.verify_pattern, len);
		break;
	case 2:
	case 3:
	case 4: {
		unsigned int pattern = td->o.verify_pattern;
		unsigned int i = 0;
		unsigned char c1, c2, c3, c4;
		unsigned char *b = p;

		dprint(FD_VERIFY, "fill verify pattern b=%d len=%u\n",
					td->o.verify_pattern_bytes, len);

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
		log_info("%02x", p[i]);
	log_info("\n");
}

/*
 * Prepare for seperation of verify_header and checksum header
 */
static inline unsigned int __hdr_size(int verify_type)
{
	unsigned int len = len;

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
				    struct io_u *io_u, unsigned char header_num)
{
	return io_u->buf + header_num * hdr->len + hdr_size(hdr);
}

static int verify_io_u_meta(struct verify_header *hdr, struct thread_data *td,
			    struct io_u *io_u, unsigned int header_num)
{
	struct vhdr_meta *vh = hdr_priv(hdr);

	dprint(FD_VERIFY, "meta verify io_u %p, len %u\n", io_u, hdr->len);

	if (vh->offset != io_u->offset + header_num * td->o.verify_interval) {
		log_err("meta: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		return EILSEQ;
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

	dprint(FD_VERIFY, "sha512 verify io_u %p, len %u\n", io_u, hdr->len);

	sha512_init(&sha512_ctx);
	sha512_update(&sha512_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->sha512, sha512_ctx.buf, sizeof(sha512))) {
		log_err("sha512: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		hexdump(vh->sha512, sizeof(vh->sha512));
		hexdump(sha512_ctx.buf, sizeof(sha512));
		return EILSEQ;
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

	dprint(FD_VERIFY, "sha256 verify io_u %p, len %u\n", io_u, hdr->len);

	sha256_init(&sha256_ctx);
	sha256_update(&sha256_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->sha256, sha256_ctx.buf, sizeof(sha256))) {
		log_err("sha256: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		hexdump(vh->sha256, sizeof(vh->sha256));
		hexdump(sha256_ctx.buf, sizeof(sha256));
		return EILSEQ;
	}

	return 0;
}

static int verify_io_u_crc7(struct verify_header *hdr, struct io_u *io_u,
			    unsigned char header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc7 *vh = hdr_priv(hdr);
	unsigned char c;

	dprint(FD_VERIFY, "crc7 verify io_u %p, len %u\n", io_u, hdr->len);

	c = crc7(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc7) {
		log_err("crc7: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		log_err("crc7: wanted %x, got %x\n", vh->crc7, c);
		return EILSEQ;
	}

	return 0;
}

static int verify_io_u_crc16(struct verify_header *hdr, struct io_u *io_u,
			     unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc16 *vh = hdr_priv(hdr);
	unsigned short c;

	dprint(FD_VERIFY, "crc16 verify io_u %p, len %u\n", io_u, hdr->len);

	c = crc16(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc16) {
		log_err("crc16: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		log_err("crc16: wanted %x, got %x\n", vh->crc16, c);
		return EILSEQ;
	}

	return 0;
}

static int verify_io_u_crc64(struct verify_header *hdr, struct io_u *io_u,
			     unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc64 *vh = hdr_priv(hdr);
	unsigned long long c;

	dprint(FD_VERIFY, "crc64 verify io_u %p, len %u\n", io_u, hdr->len);

	c = crc64(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc64) {
		log_err("crc64: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len,
				hdr->len);
		log_err("crc64: wanted %llx, got %llx\n",
					(unsigned long long) vh->crc64, c);
		return EILSEQ;
	}

	return 0;
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u,
			     unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32 verify io_u %p, len %u\n", io_u, hdr->len);

	c = crc32(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc32) {
		log_err("crc32: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		log_err("crc32: wanted %x, got %x\n", vh->crc32, c);
		return EILSEQ;
	}

	return 0;
}

static int verify_io_u_crc32c(struct verify_header *hdr, struct io_u *io_u,
			      unsigned int header_num)
{
	void *p = io_u_verify_off(hdr, io_u, header_num);
	struct vhdr_crc32 *vh = hdr_priv(hdr);
	uint32_t c;

	dprint(FD_VERIFY, "crc32c verify io_u %p, len %u\n", io_u, hdr->len);

	if (hdr->verify_type == VERIFY_CRC32C_INTEL)
		c = crc32c_intel(p, hdr->len - hdr_size(hdr));
	else
		c = crc32c(p, hdr->len - hdr_size(hdr));

	if (c != vh->crc32) {
		log_err("crc32c: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		log_err("crc32c: wanted %x, got %x\n", vh->crc32, c);
		return EILSEQ;
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

	dprint(FD_VERIFY, "md5 verify io_u %p, len %u\n", io_u, hdr->len);

	md5_init(&md5_ctx);
	md5_update(&md5_ctx, p, hdr->len - hdr_size(hdr));

	if (memcmp(vh->md5_digest, md5_ctx.hash, sizeof(hash))) {
		log_err("md5: verify failed at %llu/%u\n",
				io_u->offset + header_num * hdr->len, hdr->len);
		hexdump(vh->md5_digest, sizeof(vh->md5_digest));
		hexdump(md5_ctx.hash, sizeof(hash));
		return EILSEQ;
	}

	return 0;
}

static unsigned int hweight8(unsigned int w)
{
	unsigned int res = w - ((w >> 1) & 0x55);

	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res + (res >> 4)) & 0x0F;
}

int verify_io_u_pattern(unsigned long pattern, unsigned long pattern_size,
			char *buf, unsigned int len, unsigned int mod)
{
	unsigned int i;
	char split_pattern[4];

	for (i = 0; i < 4; i++) {
		split_pattern[i] = pattern & 0xff;
		pattern >>= 8;
	}

	for (i = 0; i < len; i++) {
		if (buf[i] != split_pattern[mod]) {
			unsigned int bits;

			bits = hweight8(buf[i] ^ split_pattern[mod]);
			log_err("fio: got pattern %x, wanted %x. Bad bits %d\n",
				buf[i], split_pattern[mod], bits);
			log_err("fio: bad pattern block offset %u\n", i);
			return EILSEQ;
		}
		mod++;
		if (mod == pattern_size)
			mod = 0;
	}

	return 0;
}

/*
 * Push IO verification to a separate thread
 */
int verify_io_u_async(struct thread_data *td, struct io_u *io_u)
{
	if (io_u->file)
		put_file_log(td, io_u->file);

	io_u->file = NULL;

	pthread_mutex_lock(&td->io_u_lock);
	flist_del(&io_u->list);
	flist_add_tail(&io_u->list, &td->verify_list);
	pthread_mutex_unlock(&td->io_u_lock);

	pthread_cond_signal(&td->verify_cond);
	io_u->flags |= IO_U_F_FREE_DEF;
	return 0;
}

int verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	struct verify_header *hdr;
	unsigned int hdr_size, hdr_inc, hdr_num = 0;
	void *p;
	int ret;

	if (td->o.verify == VERIFY_NULL || io_u->ddir != DDIR_READ)
		return 0;

	hdr_inc = io_u->buflen;
	if (td->o.verify_interval)
		hdr_inc = td->o.verify_interval;

	ret = 0;
	for (p = io_u->buf; p < io_u->buf + io_u->buflen;
	     p += hdr_inc, hdr_num++) {
		if (ret && td->o.verify_fatal) {
			td->terminate = 1;
			break;
		}
		hdr_size = __hdr_size(td->o.verify);
		if (td->o.verify_offset)
			memswp(p, p + td->o.verify_offset, hdr_size);
		hdr = p;

		if (hdr->fio_magic != FIO_HDR_MAGIC) {
			log_err("Bad verify header %x\n", hdr->fio_magic);
			return EILSEQ;
		}

		if (td->o.verify_pattern_bytes) {
			dprint(FD_VERIFY, "pattern verify io_u %p, len %u\n",
								io_u, hdr->len);
			ret = verify_io_u_pattern(td->o.verify_pattern,
						  td->o.verify_pattern_bytes,
						  p + hdr_size,
						  hdr_inc - hdr_size,
						  hdr_size % 4);
			/*
			 * Also verify the meta data, if applicable
			 */
			if (hdr->verify_type == VERIFY_META)
				ret |= verify_io_u_meta(hdr, td, io_u, hdr_num);

			if (ret)
				log_err("fio: verify failed at %llu/%u\n",
					io_u->offset + hdr_num * hdr->len,
					hdr->len);
			continue;
		}

		switch (hdr->verify_type) {
		case VERIFY_MD5:
			ret = verify_io_u_md5(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC64:
			ret = verify_io_u_crc64(hdr, io_u, hdr_num);
			break;
		case VERIFY_CRC32C:
		case VERIFY_CRC32C_INTEL:
			ret = verify_io_u_crc32c(hdr, io_u, hdr_num);
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
			ret = EINVAL;
		}
	}

	return ret;
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

static void fill_crc32c(struct verify_header *hdr, void *p, unsigned int len)
{
	struct vhdr_crc32 *vh = hdr_priv(hdr);

	if (hdr->verify_type == VERIFY_CRC32C_INTEL)
		vh->crc32 = crc32c_intel(p, len);
	else
		vh->crc32 = crc32c(p, len);
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

	for (; p < io_u->buf + io_u->buflen; p += hdr_inc) {
		hdr = p;

		hdr->fio_magic = FIO_HDR_MAGIC;
		hdr->verify_type = td->o.verify;
		hdr->len = hdr_inc;
		data_len = hdr_inc - hdr_size(hdr);

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
		case VERIFY_META:
			dprint(FD_VERIFY, "fill meta io_u %p, len %u\n",
							io_u, hdr->len);
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
	} else if (!flist_empty(&td->io_hist_list)) {
		ipo = flist_entry(td->io_hist_list.next, struct io_piece, list);
		flist_del(&ipo->list);
	}

	if (ipo) {
		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->file = ipo->file;

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
		free(ipo);
		dprint(FD_VERIFY, "get_next_verify: ret io_u %p\n", io_u);
		return 0;
	}

	dprint(FD_VERIFY, "get_next_verify: empty\n");
	return 1;
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
			io_u = flist_entry(list.next, struct io_u, list);
			flist_del_init(&io_u->list);

			ret = verify_io_u(td, io_u);
			put_io_u(td, io_u);
			if (!ret)
				continue;
			if (td->o.continue_on_error &&
			    td_non_fatal_error(ret)) {
				update_error_count(td, ret);
				td_clear_error(td);
				ret = 0;
			}
		}
	} while (!ret);

	if (ret) {
		td_verror(td, ret, "async_verify");
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

	td->verify_thread_exit = 0;

	td->verify_threads = malloc(sizeof(pthread_t) * td->o.verify_async);
	for (i = 0; i < td->o.verify_async; i++) {
		ret = pthread_create(&td->verify_threads[i], NULL,
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
