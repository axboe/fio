#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "output_buffer.h"
#include "../log.h"

#define BUF_INC	1024

void buf_output_init(struct buf_output *out)
{
	out->max_buflen = 0;
	out->buflen = 0;
	out->buf = NULL;
}

void buf_output_free(struct buf_output *out)
{
	free(out->buf);
}

size_t buf_output_add(struct buf_output *out, const char *buf, size_t len)
{
	while (out->max_buflen - out->buflen < len) {
		size_t old_max = out->max_buflen;

		out->max_buflen += BUF_INC;
		out->buf = realloc(out->buf, out->max_buflen);
		memset(&out->buf[old_max], 0, BUF_INC);
	}

	memcpy(&out->buf[out->buflen], buf, len);
	out->buflen += len;
	return len;
}

size_t buf_output_flush(struct buf_output *out)
{
	size_t ret = 0;

	if (out->buflen) {
		ret = log_local_buf(out->buf, out->buflen);
		memset(out->buf, 0, out->max_buflen);
		out->buflen = 0;
	}

	return ret;
}
