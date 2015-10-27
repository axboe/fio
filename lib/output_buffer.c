#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "output_buffer.h"
#include "../log.h"

#define BUF_INC	1024

void buf_output_init(struct buf_output *out, int index)
{
	out->max_buflen = BUF_INC;
	out->buf = malloc(out->max_buflen);
	memset(out->buf, 0, out->max_buflen);
	out->buflen = 0;
}

void buf_output_free(struct buf_output *out)
{
	free(out->buf);
}

void buf_output_add(struct buf_output *out, const char *buf, size_t len)
{
	while (out->max_buflen - out->buflen < len) {
		size_t newlen = out->max_buflen + BUF_INC - out->buflen;

		out->buf = realloc(out->buf, out->max_buflen + BUF_INC);
		out->max_buflen += BUF_INC;
		memset(&out->buf[out->buflen], 0, newlen);
	}

	memcpy(&out->buf[out->buflen], buf, len);
	out->buflen += len;
}

void buf_output_flush(struct buf_output *out)
{
	if (out->buflen) {
		log_local_buf(out->buf, out->buflen);
		memset(out->buf, 0, out->max_buflen);
		out->buflen = 0;
	}
}
