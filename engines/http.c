/*
 * HTTP GET/PUT IO engine
 *
 * IO engine to perform HTTP(S) GET/PUT requests via libcurl-easy.
 *
 * Copyright (C) 2018 SUSE LLC
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include <pthread.h>
#include <time.h>
#include <curl/curl.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "fio.h"
#include "../optgroup.h"


enum {
	FIO_HTTP_WEBDAV	    = 0,
	FIO_HTTP_S3	    = 1,
	FIO_HTTP_SWIFT	    = 2,

	FIO_HTTPS_OFF	    = 0,
	FIO_HTTPS_ON	    = 1,
	FIO_HTTPS_INSECURE  = 2,
};

struct http_data {
	CURL *curl;
};

struct http_options {
	void *pad;
	unsigned int https;
	char *host;
	char *user;
	char *pass;
	char *s3_key;
	char *s3_keyid;
	char *s3_region;
	char *swift_auth_token;
	int verbose;
	unsigned int mode;
};

struct http_curl_stream {
	char *buf;
	size_t pos;
	size_t max;
};

static struct fio_option options[] = {
	{
		.name     = "https",
		.lname    = "https",
		.type     = FIO_OPT_STR,
		.help     = "Enable https",
		.off1     = offsetof(struct http_options, https),
		.def      = "off",
		.posval = {
			  { .ival = "off",
			    .oval = FIO_HTTPS_OFF,
			    .help = "No HTTPS",
			  },
			  { .ival = "on",
			    .oval = FIO_HTTPS_ON,
			    .help = "Enable HTTPS",
			  },
			  { .ival = "insecure",
			    .oval = FIO_HTTPS_INSECURE,
			    .help = "Enable HTTPS, disable peer verification",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_host",
		.lname    = "http_host",
		.type     = FIO_OPT_STR_STORE,
		.help     = "Hostname (S3 bucket)",
		.off1     = offsetof(struct http_options, host),
		.def	  = "localhost",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_user",
		.lname    = "http_user",
		.type     = FIO_OPT_STR_STORE,
		.help     = "HTTP user name",
		.off1     = offsetof(struct http_options, user),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_pass",
		.lname    = "http_pass",
		.type     = FIO_OPT_STR_STORE,
		.help     = "HTTP password",
		.off1     = offsetof(struct http_options, pass),
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_s3_key",
		.lname    = "S3 secret key",
		.type     = FIO_OPT_STR_STORE,
		.help     = "S3 secret key",
		.off1     = offsetof(struct http_options, s3_key),
		.def	  = "",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_s3_keyid",
		.lname    = "S3 key id",
		.type     = FIO_OPT_STR_STORE,
		.help     = "S3 key id",
		.off1     = offsetof(struct http_options, s3_keyid),
		.def	  = "",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_swift_auth_token",
		.lname    = "Swift auth token",
		.type     = FIO_OPT_STR_STORE,
		.help     = "OpenStack Swift auth token",
		.off1     = offsetof(struct http_options, swift_auth_token),
		.def	  = "",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_s3_region",
		.lname    = "S3 region",
		.type     = FIO_OPT_STR_STORE,
		.help     = "S3 region",
		.off1     = offsetof(struct http_options, s3_region),
		.def	  = "us-east-1",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_mode",
		.lname    = "Request mode to use",
		.type     = FIO_OPT_STR,
		.help     = "Whether to use WebDAV, Swift, or S3",
		.off1     = offsetof(struct http_options, mode),
		.def	  = "webdav",
		.posval = {
			  { .ival = "webdav",
			    .oval = FIO_HTTP_WEBDAV,
			    .help = "WebDAV server",
			  },
			  { .ival = "s3",
			    .oval = FIO_HTTP_S3,
			    .help = "S3 storage backend",
			  },
			  { .ival = "swift",
			    .oval = FIO_HTTP_SWIFT,
			    .help = "OpenStack Swift storage",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = "http_verbose",
		.lname    = "HTTP verbosity level",
		.type     = FIO_OPT_INT,
		.help     = "increase http engine verbosity",
		.off1     = offsetof(struct http_options, verbose),
		.def	  = "0",
		.category = FIO_OPT_C_ENGINE,
		.group    = FIO_OPT_G_HTTP,
	},
	{
		.name     = NULL,
	},
};

static char *_aws_uriencode(const char *uri)
{
	size_t bufsize = 1024;
	char *r = malloc(bufsize);
	char c;
	int i, n;
	const char *hex = "0123456789ABCDEF";

	if (!r) {
		log_err("malloc failed\n");
		return NULL;
	}

	n = 0;
	for (i = 0; (c = uri[i]); i++) {
		if (n > bufsize-5) {
			log_err("encoding the URL failed\n");
			return NULL;
		}

		if ( (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
		|| (c >= '0' && c <= '9') || c == '_' || c == '-'
		|| c == '~' || c == '.' || c == '/')
			r[n++] = c;
		else {
			r[n++] = '%';
			r[n++] = hex[(c >> 4 ) & 0xF];
			r[n++] = hex[c & 0xF];
		}
	}
	r[n++] = 0;
	return r;
}

static char *_conv_hex(const unsigned char *p, size_t len)
{
	char *r;
	int i,n;
	const char *hex = "0123456789abcdef";
	r = malloc(len * 2 + 1);
	n = 0;
	for (i = 0; i < len; i++) {
		r[n++] = hex[(p[i] >> 4 ) & 0xF];
		r[n++] = hex[p[i] & 0xF];
	}
	r[n] = 0;

	return r;
}

static char *_gen_hex_sha256(const char *p, size_t len)
{
	unsigned char hash[SHA256_DIGEST_LENGTH];

	SHA256((unsigned char*)p, len, hash);
	return _conv_hex(hash, SHA256_DIGEST_LENGTH);
}

static char *_gen_hex_md5(const char *p, size_t len)
{
	unsigned char hash[MD5_DIGEST_LENGTH];

	MD5((unsigned char*)p, len, hash);
	return _conv_hex(hash, MD5_DIGEST_LENGTH);
}

static void _hmac(unsigned char *md, void *key, int key_len, char *data) {
#ifndef CONFIG_HAVE_OPAQUE_HMAC_CTX
	HMAC_CTX _ctx;
#endif
	HMAC_CTX *ctx;
	unsigned int hmac_len;

#ifdef CONFIG_HAVE_OPAQUE_HMAC_CTX
	ctx = HMAC_CTX_new();
#else
	ctx = &_ctx;
	/* work-around crash in certain versions of libssl */
	HMAC_CTX_init(ctx);
#endif
	HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL);
	HMAC_Update(ctx, (unsigned char*)data, strlen(data));
	HMAC_Final(ctx, md, &hmac_len);
#ifdef CONFIG_HAVE_OPAQUE_HMAC_CTX
	HMAC_CTX_free(ctx);
#else
	HMAC_CTX_cleanup(ctx);
#endif
}

static int _curl_trace(CURL *handle, curl_infotype type,
	     char *data, size_t size,
	     void *userp)
{
	const char *text;
	(void)handle; /* prevent compiler warning */
	(void)userp;

	switch (type) {
	case CURLINFO_TEXT:
		fprintf(stderr, "== Info: %s", data);
		/* fall through */
	default:
	case CURLINFO_SSL_DATA_OUT:
		/* fall through */
	case CURLINFO_SSL_DATA_IN:
		return 0;

	case CURLINFO_HEADER_OUT:
		text = "=> Send header";
		break;
	case CURLINFO_DATA_OUT:
		text = "=> Send data";
		break;
	case CURLINFO_HEADER_IN:
		text = "<= Recv header";
		break;
	case CURLINFO_DATA_IN:
		text = "<= Recv data";
		break;
	}

	log_info("%s: %s", text, data);
	return 0;
}

/* https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
 * https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html#signing-request-intro
 */
static void _add_aws_auth_header(CURL *curl, struct curl_slist *slist, struct http_options *o,
		int op, const char *uri, char *buf, size_t len)
{
	char date_short[16];
	char date_iso[32];
	char method[8];
	char dkey[128];
	char creq[512];
	char sts[256];
	char s[512];
	char *uri_encoded = NULL;
	char *dsha = NULL;
	char *csha = NULL;
	char *signature = NULL;
	const char *service = "s3";
	const char *aws = "aws4_request";
	unsigned char md[SHA256_DIGEST_LENGTH];

	time_t t = time(NULL);
	struct tm *gtm = gmtime(&t);

	strftime (date_short, sizeof(date_short), "%Y%m%d", gtm);
	strftime (date_iso, sizeof(date_iso), "%Y%m%dT%H%M%SZ", gtm);
	uri_encoded = _aws_uriencode(uri);

	if (op == DDIR_WRITE) {
		dsha = _gen_hex_sha256(buf, len);
		sprintf(method, "PUT");
	} else {
		/* DDIR_READ && DDIR_TRIM supply an empty body */
		if (op == DDIR_READ)
			sprintf(method, "GET");
		else
			sprintf(method, "DELETE");
		dsha = _gen_hex_sha256("", 0);
	}

	/* Create the canonical request first */
	snprintf(creq, sizeof(creq),
	"%s\n"
	"%s\n"
	"\n"
	"host:%s\n"
	"x-amz-content-sha256:%s\n"
	"x-amz-date:%s\n"
	"\n"
	"host;x-amz-content-sha256;x-amz-date\n"
	"%s"
	, method
	, uri_encoded, o->host, dsha, date_iso, dsha);

	csha = _gen_hex_sha256(creq, strlen(creq));
	snprintf(sts, sizeof(sts), "AWS4-HMAC-SHA256\n%s\n%s/%s/%s/%s\n%s",
		date_iso, date_short, o->s3_region, service, aws, csha);

	snprintf((char *)dkey, sizeof(dkey), "AWS4%s", o->s3_key);
	_hmac(md, dkey, strlen(dkey), date_short);
	_hmac(md, md, SHA256_DIGEST_LENGTH, o->s3_region);
	_hmac(md, md, SHA256_DIGEST_LENGTH, (char*) service);
	_hmac(md, md, SHA256_DIGEST_LENGTH, (char*) aws);
	_hmac(md, md, SHA256_DIGEST_LENGTH, sts);

	signature = _conv_hex(md, SHA256_DIGEST_LENGTH);

	/* Surpress automatic Accept: header */
	slist = curl_slist_append(slist, "Accept:");

	snprintf(s, sizeof(s), "x-amz-content-sha256: %s", dsha);
	slist = curl_slist_append(slist, s);

	snprintf(s, sizeof(s), "x-amz-date: %s", date_iso);
	slist = curl_slist_append(slist, s);

	snprintf(s, sizeof(s), "Authorization: AWS4-HMAC-SHA256 Credential=%s/%s/%s/s3/aws4_request,"
	"SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=%s",
	o->s3_keyid, date_short, o->s3_region, signature);
	slist = curl_slist_append(slist, s);

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

	free(uri_encoded);
	free(csha);
	free(dsha);
	free(signature);
}

static void _add_swift_header(CURL *curl, struct curl_slist *slist, struct http_options *o,
		int op, const char *uri, char *buf, size_t len)
{
	char *dsha = NULL;
	char s[512];

	if (op == DDIR_WRITE) {
		dsha = _gen_hex_md5(buf, len);
	}
	/* Surpress automatic Accept: header */
	slist = curl_slist_append(slist, "Accept:");

	snprintf(s, sizeof(s), "etag: %s", dsha);
	slist = curl_slist_append(slist, s);

	snprintf(s, sizeof(s), "x-auth-token: %s", o->swift_auth_token);
	slist = curl_slist_append(slist, s);

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);

	free(dsha);
}

static void fio_http_cleanup(struct thread_data *td)
{
	struct http_data *http = td->io_ops_data;

	if (http) {
		curl_easy_cleanup(http->curl);
		free(http);
	}
}

static size_t _http_read(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct http_curl_stream *state = stream;
	size_t len = size * nmemb;
	/* We're retrieving; nothing is supposed to be read locally */
	if (!stream)
		return 0;
	if (len+state->pos > state->max)
		len = state->max - state->pos;
	memcpy(ptr, &state->buf[state->pos], len);
	state->pos += len;
	return len;
}

static size_t _http_write(void *ptr, size_t size, size_t nmemb, void *stream)
{
	struct http_curl_stream *state = stream;
	/* We're just discarding the returned body after a PUT */
	if (!stream)
		return nmemb;
	if (size != 1)
		return CURLE_WRITE_ERROR;
	if (nmemb + state->pos > state->max)
		return CURLE_WRITE_ERROR;
	memcpy(&state->buf[state->pos], ptr, nmemb);
	state->pos += nmemb;
	return nmemb;
}

static int _http_seek(void *stream, curl_off_t offset, int origin)
{
	struct http_curl_stream *state = stream;
	if (offset < state->max && origin == SEEK_SET) {
		state->pos = offset;
		return CURL_SEEKFUNC_OK;
	} else
		return CURL_SEEKFUNC_FAIL;
}

static enum fio_q_status fio_http_queue(struct thread_data *td,
					 struct io_u *io_u)
{
	struct http_data *http = td->io_ops_data;
	struct http_options *o = td->eo;
	struct http_curl_stream _curl_stream;
	struct curl_slist *slist = NULL;
	char object[512];
	char url[1024];
	long status;
	CURLcode res;
	int r = -1;

	fio_ro_check(td, io_u);
	memset(&_curl_stream, 0, sizeof(_curl_stream));
	snprintf(object, sizeof(object), "%s_%llu_%llu", td->files[0]->file_name,
		io_u->offset, io_u->xfer_buflen);
	if (o->https == FIO_HTTPS_OFF)
		snprintf(url, sizeof(url), "http://%s%s", o->host, object);
	else
		snprintf(url, sizeof(url), "https://%s%s", o->host, object);
	curl_easy_setopt(http->curl, CURLOPT_URL, url);
	_curl_stream.buf = io_u->xfer_buf;
	_curl_stream.max = io_u->xfer_buflen;
	curl_easy_setopt(http->curl, CURLOPT_SEEKDATA, &_curl_stream);
	curl_easy_setopt(http->curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)io_u->xfer_buflen);

	if (o->mode == FIO_HTTP_S3)
		_add_aws_auth_header(http->curl, slist, o, io_u->ddir, object,
			io_u->xfer_buf, io_u->xfer_buflen);
	else if (o->mode == FIO_HTTP_SWIFT)
		_add_swift_header(http->curl, slist, o, io_u->ddir, object,
			io_u->xfer_buf, io_u->xfer_buflen);

	if (io_u->ddir == DDIR_WRITE) {
		curl_easy_setopt(http->curl, CURLOPT_READDATA, &_curl_stream);
		curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, NULL);
		curl_easy_setopt(http->curl, CURLOPT_UPLOAD, 1L);
		res = curl_easy_perform(http->curl);
		if (res == CURLE_OK) {
			curl_easy_getinfo(http->curl, CURLINFO_RESPONSE_CODE, &status);
			if (status == 100 || (status >= 200 && status <= 204))
				goto out;
			log_err("DDIR_WRITE failed with HTTP status code %ld\n", status);
			goto err;
		}
	} else if (io_u->ddir == DDIR_READ) {
		curl_easy_setopt(http->curl, CURLOPT_READDATA, NULL);
		curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, &_curl_stream);
		curl_easy_setopt(http->curl, CURLOPT_HTTPGET, 1L);
		res = curl_easy_perform(http->curl);
		if (res == CURLE_OK) {
			curl_easy_getinfo(http->curl, CURLINFO_RESPONSE_CODE, &status);
			if (status == 200)
				goto out;
			else if (status == 404) {
				/* Object doesn't exist. Pretend we read
				 * zeroes */
				memset(io_u->xfer_buf, 0, io_u->xfer_buflen);
				goto out;
			}
			log_err("DDIR_READ failed with HTTP status code %ld\n", status);
		}
		goto err;
	} else if (io_u->ddir == DDIR_TRIM) {
		curl_easy_setopt(http->curl, CURLOPT_HTTPGET, 1L);
		curl_easy_setopt(http->curl, CURLOPT_CUSTOMREQUEST, "DELETE");
		curl_easy_setopt(http->curl, CURLOPT_INFILESIZE_LARGE, (curl_off_t)0);
		curl_easy_setopt(http->curl, CURLOPT_READDATA, NULL);
		curl_easy_setopt(http->curl, CURLOPT_WRITEDATA, NULL);
		res = curl_easy_perform(http->curl);
		if (res == CURLE_OK) {
			curl_easy_getinfo(http->curl, CURLINFO_RESPONSE_CODE, &status);
			if (status == 200 || status == 202 || status == 204 || status == 404)
				goto out;
			log_err("DDIR_TRIM failed with HTTP status code %ld\n", status);
		}
		goto err;
	}

	log_err("WARNING: Only DDIR_READ/DDIR_WRITE/DDIR_TRIM are supported!\n");

err:
	io_u->error = r;
	td_verror(td, io_u->error, "transfer");
out:
	curl_slist_free_all(slist);
	return FIO_Q_COMPLETED;
}

static struct io_u *fio_http_event(struct thread_data *td, int event)
{
	/* sync IO engine - never any outstanding events */
	return NULL;
}

int fio_http_getevents(struct thread_data *td, unsigned int min,
	unsigned int max, const struct timespec *t)
{
	/* sync IO engine - never any outstanding events */
	return 0;
}

static int fio_http_setup(struct thread_data *td)
{
	struct http_data *http = NULL;
	struct http_options *o = td->eo;

	/* allocate engine specific structure to deal with libhttp. */
	http = calloc(1, sizeof(*http));
	if (!http) {
		log_err("calloc failed.\n");
		goto cleanup;
	}

	http->curl = curl_easy_init();
	if (o->verbose)
		curl_easy_setopt(http->curl, CURLOPT_VERBOSE, 1L);
	if (o->verbose > 1)
		curl_easy_setopt(http->curl, CURLOPT_DEBUGFUNCTION, &_curl_trace);
	curl_easy_setopt(http->curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(http->curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(http->curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
	if (o->https == FIO_HTTPS_INSECURE) {
		curl_easy_setopt(http->curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(http->curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	curl_easy_setopt(http->curl, CURLOPT_READFUNCTION, _http_read);
	curl_easy_setopt(http->curl, CURLOPT_WRITEFUNCTION, _http_write);
	curl_easy_setopt(http->curl, CURLOPT_SEEKFUNCTION, &_http_seek);
	if (o->user && o->pass) {
		curl_easy_setopt(http->curl, CURLOPT_USERNAME, o->user);
		curl_easy_setopt(http->curl, CURLOPT_PASSWORD, o->pass);
		curl_easy_setopt(http->curl, CURLOPT_HTTPAUTH, CURLAUTH_ANY);
	}

	td->io_ops_data = http;

	/* Force single process mode. */
	td->o.use_thread = 1;

	return 0;
cleanup:
	fio_http_cleanup(td);
	return 1;
}

static int fio_http_open(struct thread_data *td, struct fio_file *f)
{
	return 0;
}
static int fio_http_invalidate(struct thread_data *td, struct fio_file *f)
{
	return 0;
}

static struct ioengine_ops ioengine = {
	.name = "http",
	.version		= FIO_IOOPS_VERSION,
	.flags			= FIO_DISKLESSIO | FIO_SYNCIO,
	.setup			= fio_http_setup,
	.queue			= fio_http_queue,
	.getevents		= fio_http_getevents,
	.event			= fio_http_event,
	.cleanup		= fio_http_cleanup,
	.open_file		= fio_http_open,
	.invalidate		= fio_http_invalidate,
	.options		= options,
	.option_struct_size	= sizeof(struct http_options),
};

static void fio_init fio_http_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_http_unregister(void)
{
	unregister_ioengine(&ioengine);
}
