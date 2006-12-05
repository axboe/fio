/*
 * IO verification helpers
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "fio.h"
#include "os.h"

static void fill_random_bytes(struct thread_data *td,
			      unsigned char *p, unsigned int len)
{
	unsigned int todo;
	double r;

	while (len) {
		r = os_random_double(&td->verify_state);

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

static void hexdump(void *buffer, int len)
{
	unsigned char *p = buffer;
	int i;

	for (i = 0; i < len; i++)
		fprintf(f_out, "%02x", p[i]);
	fprintf(f_out, "\n");
}

static int verify_io_u_crc32(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	unsigned long c;

	p += sizeof(*hdr);
	c = crc32(p, hdr->len - sizeof(*hdr));

	if (c != hdr->crc32) {
		log_err("crc32: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		log_err("crc32: wanted %lx, got %lx\n", hdr->crc32, c);
		return 1;
	}

	return 0;
}

static int verify_io_u_md5(struct verify_header *hdr, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	p += sizeof(*hdr);
	md5_update(&md5_ctx, p, hdr->len - sizeof(*hdr));

	if (memcmp(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash))) {
		log_err("md5: verify failed at %llu/%u\n", io_u->offset, io_u->buflen);
		hexdump(hdr->md5_digest, sizeof(hdr->md5_digest));
		hexdump(md5_ctx.hash, sizeof(md5_ctx.hash));
		return 1;
	}

	return 0;
}

static int verify_io_u(struct io_u *io_u)
{
	struct verify_header *hdr = (struct verify_header *) io_u->buf;
	int ret;

	if (hdr->fio_magic != FIO_HDR_MAGIC)
		return 1;

	if (hdr->verify_type == VERIFY_MD5)
		ret = verify_io_u_md5(hdr, io_u);
	else if (hdr->verify_type == VERIFY_CRC32)
		ret = verify_io_u_crc32(hdr, io_u);
	else {
		log_err("Bad verify type %u\n", hdr->verify_type);
		ret = 1;
	}

	return ret;
}

static void fill_crc32(struct verify_header *hdr, void *p, unsigned int len)
{
	hdr->crc32 = crc32(p, len);
}

static void fill_md5(struct verify_header *hdr, void *p, unsigned int len)
{
	struct md5_ctx md5_ctx;

	memset(&md5_ctx, 0, sizeof(md5_ctx));
	md5_update(&md5_ctx, p, len);
	memcpy(hdr->md5_digest, md5_ctx.hash, sizeof(md5_ctx.hash));
}

/*
 * fill body of io_u->buf with random data and add a header with the
 * crc32 or md5 sum of that data.
 */
void populate_verify_io_u(struct thread_data *td, struct io_u *io_u)
{
	unsigned char *p = (unsigned char *) io_u->buf;
	struct verify_header hdr;

	hdr.fio_magic = FIO_HDR_MAGIC;
	hdr.len = io_u->buflen;
	p += sizeof(hdr);
	fill_random_bytes(td, p, io_u->buflen - sizeof(hdr));

	if (td->verify == VERIFY_MD5) {
		fill_md5(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_MD5;
	} else {
		fill_crc32(&hdr, p, io_u->buflen - sizeof(hdr));
		hdr.verify_type = VERIFY_CRC32;
	}

	memcpy(io_u->buf, &hdr, sizeof(hdr));
}

int get_next_verify(struct thread_data *td, struct io_u *io_u)
{
	struct io_piece *ipo;

	if (!list_empty(&td->io_hist_list)) {
		ipo = list_entry(td->io_hist_list.next, struct io_piece, list);

		list_del(&ipo->list);

		io_u->offset = ipo->offset;
		io_u->buflen = ipo->len;
		io_u->ddir = DDIR_READ;
		free(ipo);
		return 0;
	}

	return 1;
}

int do_io_u_verify(struct thread_data *td, struct io_u **io_u)
{
	struct io_u *v_io_u = *io_u;
	int ret = 0;

	if (v_io_u) {
		ret = verify_io_u(v_io_u);
		put_io_u(td, v_io_u);
		*io_u = NULL;
	}

	return ret;
}
