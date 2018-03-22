#ifndef FIO_PARSE_PATTERN_H
#define FIO_PARSE_PATTERN_H

/**
 * Pattern format description. The input for 'parse_pattern'.
 * Describes format with its name and callback, which should
 * be called to paste something inside the buffer.
 */
struct pattern_fmt_desc {
	const char  *fmt;
	unsigned int len;
	int (*paste)(char *buf, unsigned int len, void *priv);
};

/**
 * Pattern format. The output of 'parse_pattern'.
 * Describes the exact position inside the xbuffer.
 */
struct pattern_fmt {
	unsigned int off;
	const struct pattern_fmt_desc *desc;
};

int parse_and_fill_pattern(const char *in, unsigned int in_len,
			   char *out, unsigned int out_len,
			   const struct pattern_fmt_desc *fmt_desc,
			   unsigned int fmt_desc_sz,
			   struct pattern_fmt *fmt,
			   unsigned int *fmt_sz_out);

int paste_format_inplace(char *pattern, unsigned int pattern_len,
			 struct pattern_fmt *fmt, unsigned int fmt_sz,
			 void *priv);

int paste_format(const char *pattern, unsigned int pattern_len,
		 struct pattern_fmt *fmt, unsigned int fmt_sz,
		 char *out, unsigned int out_len, void *priv);

int cpy_pattern(const char *pattern, unsigned int pattern_len,
		char *out, unsigned int out_len);

int cmp_pattern(const char *pattern, unsigned int pattern_size,
		unsigned int off, const char *buf, unsigned int len);

#endif
