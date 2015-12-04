#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "output_buffer.h"
#include "../log.h"
#include "../minmax.h"

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
	if (out->max_buflen - out->buflen < len) {
		size_t need = len - (out->max_buflen - out->buflen);
		size_t old_max = out->max_buflen;

		need = max((size_t) BUF_INC, need);
		out->max_buflen += need;
		out->buf = realloc(out->buf, out->max_buflen);

		old_max = max(old_max, out->buflen + len);
		if (old_max + need > out->max_buflen)
			need = out->max_buflen - old_max;
		memset(&out->buf[old_max], 0, need);
	}

	memcpy(&out->buf[out->buflen], buf, len);
	out->buflen += len;
	return len;
}

size_t buf_output_flush(struct buf_output *out)
{
	size_t ret = 0;

	if (out->buflen) {
		ret = log_info_buf(out->buf, out->buflen);
		memset(out->buf, 0, out->max_buflen);
		out->buflen = 0;
	}

	return ret;
}
