#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#ifdef CONFIG_ZLIB
#include <zlib.h>
#endif

#include "fio.h"
#include "client.h"
#include "server.h"
#include "flist.h"
#include "hash.h"
#include "verify.h"

static void handle_du(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_ts(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_gs(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_probe(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_text(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_stop(struct fio_client *client, struct fio_net_cmd *cmd);
static void handle_start(struct fio_client *client, struct fio_net_cmd *cmd);

static void convert_text(struct fio_net_cmd *cmd);

struct client_ops fio_client_ops = {
	.text		= handle_text,
	.disk_util	= handle_du,
	.thread_status	= handle_ts,
	.group_stats	= handle_gs,
	.stop		= handle_stop,
	.start		= handle_start,
	.eta		= display_thread_status,
	.probe		= handle_probe,
	.eta_msec	= FIO_CLIENT_DEF_ETA_MSEC,
	.client_type	= FIO_CLIENT_TYPE_CLI,
};

static struct timeval eta_tv;

static FLIST_HEAD(client_list);
static FLIST_HEAD(eta_list);

static FLIST_HEAD(arg_list);

struct thread_stat client_ts;
struct group_run_stats client_gs;
int sum_stat_clients;

static int sum_stat_nr;
static struct json_object *root = NULL;
static struct json_object *job_opt_object = NULL;
static struct json_array *clients_array = NULL;
static struct json_array *du_array = NULL;

static int error_clients;

#define FIO_CLIENT_HASH_BITS	7
#define FIO_CLIENT_HASH_SZ	(1 << FIO_CLIENT_HASH_BITS)
#define FIO_CLIENT_HASH_MASK	(FIO_CLIENT_HASH_SZ - 1)
static struct flist_head client_hash[FIO_CLIENT_HASH_SZ];

static struct cmd_iolog_pdu *convert_iolog(struct fio_net_cmd *, bool *);

static void fio_client_add_hash(struct fio_client *client)
{
	int bucket = hash_long(client->fd, FIO_CLIENT_HASH_BITS);

	bucket &= FIO_CLIENT_HASH_MASK;
	flist_add(&client->hash_list, &client_hash[bucket]);
}

static void fio_client_remove_hash(struct fio_client *client)
{
	if (!flist_empty(&client->hash_list))
		flist_del_init(&client->hash_list);
}

static void fio_init fio_client_hash_init(void)
{
	int i;

	for (i = 0; i < FIO_CLIENT_HASH_SZ; i++)
		INIT_FLIST_HEAD(&client_hash[i]);
}

static int read_data(int fd, void *data, size_t size)
{
	ssize_t ret;

	while (size) {
		ret = read(fd, data, size);
		if (ret < 0) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			break;
		} else if (!ret)
			break;
		else {
			data += ret;
			size -= ret;
		}
	}

	if (size)
		return EAGAIN;

	return 0;
}

static void fio_client_json_init(void)
{
	char time_buf[32];
	time_t time_p;

	if (!(output_format & FIO_OUTPUT_JSON))
		return;

	time(&time_p);
	os_ctime_r((const time_t *) &time_p, time_buf, sizeof(time_buf));
	time_buf[strlen(time_buf) - 1] = '\0';

	root = json_create_object();
	json_object_add_value_string(root, "fio version", fio_version_string);
	json_object_add_value_int(root, "timestamp", time_p);
	json_object_add_value_string(root, "time", time_buf);

	job_opt_object = json_create_object();
	json_object_add_value_object(root, "global options", job_opt_object);
	clients_array = json_create_array();
	json_object_add_value_array(root, "client_stats", clients_array);
	du_array = json_create_array();
	json_object_add_value_array(root, "disk_util", du_array);
}

static void fio_client_json_fini(void)
{
	if (!(output_format & FIO_OUTPUT_JSON))
		return;

	log_info("\n");
	json_print_object(root, NULL);
	log_info("\n");
	json_free_object(root);
	root = NULL;
	clients_array = NULL;
	du_array = NULL;
}

static struct fio_client *find_client_by_fd(int fd)
{
	int bucket = hash_long(fd, FIO_CLIENT_HASH_BITS) & FIO_CLIENT_HASH_MASK;
	struct fio_client *client;
	struct flist_head *entry;

	flist_for_each(entry, &client_hash[bucket]) {
		client = flist_entry(entry, struct fio_client, hash_list);

		if (client->fd == fd) {
			client->refs++;
			return client;
		}
	}

	return NULL;
}

void fio_put_client(struct fio_client *client)
{
	if (--client->refs)
		return;

	free(client->hostname);
	if (client->argv)
		free(client->argv);
	if (client->name)
		free(client->name);
	while (client->nr_files) {
		struct client_file *cf = &client->files[--client->nr_files];

		free(cf->file);
	}
	if (client->files)
		free(client->files);
	if (client->opt_lists)
		free(client->opt_lists);

	if (!client->did_stat)
		sum_stat_clients--;

	if (client->error)
		error_clients++;

	free(client);
}

static int fio_client_dec_jobs_eta(struct client_eta *eta, client_eta_op eta_fn)
{
	if (!--eta->pending) {
		eta_fn(&eta->eta);
		free(eta);
		return 0;
	}

	return 1;
}

static void fio_drain_client_text(struct fio_client *client)
{
	do {
		struct fio_net_cmd *cmd;

		cmd = fio_net_recv_cmd(client->fd, false);
		if (!cmd)
			break;

		if (cmd->opcode == FIO_NET_CMD_TEXT) {
			convert_text(cmd);
			client->ops->text(client, cmd);
		}

		free(cmd);
	} while (1);
}

static void remove_client(struct fio_client *client)
{
	assert(client->refs);

	dprint(FD_NET, "client: removed <%s>\n", client->hostname);

	fio_drain_client_text(client);

	if (!flist_empty(&client->list))
		flist_del_init(&client->list);

	fio_client_remove_hash(client);

	if (!flist_empty(&client->eta_list)) {
		flist_del_init(&client->eta_list);
		fio_client_dec_jobs_eta(client->eta_in_flight, client->ops->eta);
	}

	close(client->fd);
	client->fd = -1;

	if (client->ops->removed)
		client->ops->removed(client);

	nr_clients--;
	fio_put_client(client);
}

struct fio_client *fio_get_client(struct fio_client *client)
{
	client->refs++;
	return client;
}

static void __fio_client_add_cmd_option(struct fio_client *client,
					const char *opt)
{
	int index;

	index = client->argc++;
	client->argv = realloc(client->argv, sizeof(char *) * client->argc);
	client->argv[index] = strdup(opt);
	dprint(FD_NET, "client: add cmd %d: %s\n", index, opt);
}

void fio_client_add_cmd_option(void *cookie, const char *opt)
{
	struct fio_client *client = cookie;
	struct flist_head *entry;

	if (!client || !opt)
		return;

	__fio_client_add_cmd_option(client, opt);

	/*
	 * Duplicate arguments to shared client group
	 */
	flist_for_each(entry, &arg_list) {
		client = flist_entry(entry, struct fio_client, arg_list);

		__fio_client_add_cmd_option(client, opt);
	}
}

struct fio_client *fio_client_add_explicit(struct client_ops *ops,
					   const char *hostname, int type,
					   int port)
{
	struct fio_client *client;

	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	INIT_FLIST_HEAD(&client->list);
	INIT_FLIST_HEAD(&client->hash_list);
	INIT_FLIST_HEAD(&client->arg_list);
	INIT_FLIST_HEAD(&client->eta_list);
	INIT_FLIST_HEAD(&client->cmd_list);

	client->hostname = strdup(hostname);

	if (type == Fio_client_socket)
		client->is_sock = 1;
	else {
		int ipv6;

		ipv6 = type == Fio_client_ipv6;
		if (fio_server_parse_host(hostname, ipv6,
						&client->addr.sin_addr,
						&client->addr6.sin6_addr))
			goto err;

		client->port = port;
	}

	client->fd = -1;
	client->ops = ops;
	client->refs = 1;
	client->type = ops->client_type;

	__fio_client_add_cmd_option(client, "fio");

	flist_add(&client->list, &client_list);
	nr_clients++;
	dprint(FD_NET, "client: added <%s>\n", client->hostname);
	return client;
err:
	free(client);
	return NULL;
}

int fio_client_add_ini_file(void *cookie, const char *ini_file, bool remote)
{
	struct fio_client *client = cookie;
	struct client_file *cf;
	size_t new_size;
	void *new_files;

	if (!client)
		return 1;

	dprint(FD_NET, "client <%s>: add ini %s\n", client->hostname, ini_file);

	new_size = (client->nr_files + 1) * sizeof(struct client_file);
	new_files = realloc(client->files, new_size);
	if (!new_files)
		return 1;

	client->files = new_files;
	cf = &client->files[client->nr_files];
	cf->file = strdup(ini_file);
	cf->remote = remote;
	client->nr_files++;
	return 0;
}

int fio_client_add(struct client_ops *ops, const char *hostname, void **cookie)
{
	struct fio_client *existing = *cookie;
	struct fio_client *client;

	if (existing) {
		/*
		 * We always add our "exec" name as the option, hence 1
		 * means empty.
		 */
		if (existing->argc == 1)
			flist_add_tail(&existing->arg_list, &arg_list);
		else {
			while (!flist_empty(&arg_list))
				flist_del_init(arg_list.next);
		}
	}

	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	INIT_FLIST_HEAD(&client->list);
	INIT_FLIST_HEAD(&client->hash_list);
	INIT_FLIST_HEAD(&client->arg_list);
	INIT_FLIST_HEAD(&client->eta_list);
	INIT_FLIST_HEAD(&client->cmd_list);

	if (fio_server_parse_string(hostname, &client->hostname,
					&client->is_sock, &client->port,
					&client->addr.sin_addr,
					&client->addr6.sin6_addr,
					&client->ipv6))
		return -1;

	client->fd = -1;
	client->ops = ops;
	client->refs = 1;
	client->type = ops->client_type;

	__fio_client_add_cmd_option(client, "fio");

	flist_add(&client->list, &client_list);
	nr_clients++;
	dprint(FD_NET, "client: added <%s>\n", client->hostname);
	*cookie = client;
	return 0;
}

static const char *server_name(struct fio_client *client, char *buf,
			       size_t bufsize)
{
	const char *from;

	if (client->ipv6)
		from = inet_ntop(AF_INET6, (struct sockaddr *) &client->addr6.sin6_addr, buf, bufsize);
	else if (client->is_sock)
		from = "sock";
	else
		from = inet_ntop(AF_INET, (struct sockaddr *) &client->addr.sin_addr, buf, bufsize);

	return from;
}

static void probe_client(struct fio_client *client)
{
	struct cmd_client_probe_pdu pdu;
	const char *sname;
	uint64_t tag;
	char buf[64];

	dprint(FD_NET, "client: send probe\n");

#ifdef CONFIG_ZLIB
	pdu.flags = __le64_to_cpu(FIO_PROBE_FLAG_ZLIB);
#else
	pdu.flags = 0;
#endif

	sname = server_name(client, buf, sizeof(buf));
	memset(pdu.server, 0, sizeof(pdu.server));
	strncpy((char *) pdu.server, sname, sizeof(pdu.server) - 1);

	fio_net_send_cmd(client->fd, FIO_NET_CMD_PROBE, &pdu, sizeof(pdu), &tag, &client->cmd_list);
}

static int fio_client_connect_ip(struct fio_client *client)
{
	struct sockaddr *addr;
	socklen_t socklen;
	int fd, domain;

	if (client->ipv6) {
		client->addr6.sin6_family = AF_INET6;
		client->addr6.sin6_port = htons(client->port);
		domain = AF_INET6;
		addr = (struct sockaddr *) &client->addr6;
		socklen = sizeof(client->addr6);
	} else {
		client->addr.sin_family = AF_INET;
		client->addr.sin_port = htons(client->port);
		domain = AF_INET;
		addr = (struct sockaddr *) &client->addr;
		socklen = sizeof(client->addr);
	}

	fd = socket(domain, SOCK_STREAM, 0);
	if (fd < 0) {
		int ret = -errno;

		log_err("fio: socket: %s\n", strerror(errno));
		return ret;
	}

	if (connect(fd, addr, socklen) < 0) {
		int ret = -errno;

		log_err("fio: connect: %s\n", strerror(errno));
		log_err("fio: failed to connect to %s:%u\n", client->hostname,
								client->port);
		close(fd);
		return ret;
	}

	return fd;
}

static int fio_client_connect_sock(struct fio_client *client)
{
	struct sockaddr_un *addr = &client->addr_un;
	socklen_t len;
	int fd;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strncpy(addr->sun_path, client->hostname, sizeof(addr->sun_path) - 1);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		int ret = -errno;

		log_err("fio: socket: %s\n", strerror(errno));
		return ret;
	}

	len = sizeof(addr->sun_family) + strlen(addr->sun_path) + 1;
	if (connect(fd, (struct sockaddr *) addr, len) < 0) {
		int ret = -errno;

		log_err("fio: connect; %s\n", strerror(errno));
		close(fd);
		return ret;
	}

	return fd;
}

int fio_client_connect(struct fio_client *client)
{
	int fd;

	dprint(FD_NET, "client: connect to host %s\n", client->hostname);

	if (client->is_sock)
		fd = fio_client_connect_sock(client);
	else
		fd = fio_client_connect_ip(client);

	dprint(FD_NET, "client: %s connected %d\n", client->hostname, fd);

	if (fd < 0)
		return fd;

	client->fd = fd;
	fio_client_add_hash(client);
	client->state = Client_connected;

	probe_client(client);
	return 0;
}

int fio_client_terminate(struct fio_client *client)
{
	return fio_net_send_quit(client->fd);
}

static void fio_clients_terminate(void)
{
	struct flist_head *entry;
	struct fio_client *client;

	dprint(FD_NET, "client: terminate clients\n");

	flist_for_each(entry, &client_list) {
		client = flist_entry(entry, struct fio_client, list);
		fio_client_terminate(client);
	}
}

static void sig_int(int sig)
{
	dprint(FD_NET, "client: got signal %d\n", sig);
	fio_clients_terminate();
}

static void client_signal_handler(void)
{
	struct sigaction act;

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGINT, &act, NULL);

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &act, NULL);

/* Windows uses SIGBREAK as a quit signal from other applications */
#ifdef WIN32
	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_int;
	act.sa_flags = SA_RESTART;
	sigaction(SIGBREAK, &act, NULL);
#endif

	memset(&act, 0, sizeof(act));
	act.sa_handler = sig_show_status;
	act.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &act, NULL);
}

static int send_client_cmd_line(struct fio_client *client)
{
	struct cmd_single_line_pdu *cslp;
	struct cmd_line_pdu *clp;
	unsigned long offset;
	unsigned int *lens;
	void *pdu;
	size_t mem;
	int i, ret;

	dprint(FD_NET, "client: send cmdline %d\n", client->argc);

	lens = malloc(client->argc * sizeof(unsigned int));

	/*
	 * Find out how much mem we need
	 */
	for (i = 0, mem = 0; i < client->argc; i++) {
		lens[i] = strlen(client->argv[i]) + 1;
		mem += lens[i];
	}

	/*
	 * We need one cmd_line_pdu, and argc number of cmd_single_line_pdu
	 */
	mem += sizeof(*clp) + (client->argc * sizeof(*cslp));

	pdu = malloc(mem);
	clp = pdu;
	offset = sizeof(*clp);

	for (i = 0; i < client->argc; i++) {
		uint16_t arg_len = lens[i];

		cslp = pdu + offset;
		strcpy((char *) cslp->text, client->argv[i]);
		cslp->len = cpu_to_le16(arg_len);
		offset += sizeof(*cslp) + arg_len;
	}

	free(lens);
	clp->lines = cpu_to_le16(client->argc);
	clp->client_type = __cpu_to_le16(client->type);
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOBLINE, pdu, mem, NULL, NULL);
	free(pdu);
	return ret;
}

int fio_clients_connect(void)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;
	int ret;

#ifdef WIN32
	WSADATA wsd;
	WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

	dprint(FD_NET, "client: connect all\n");

	client_signal_handler();

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		ret = fio_client_connect(client);
		if (ret) {
			remove_client(client);
			continue;
		}

		if (client->argc > 1)
			send_client_cmd_line(client);
	}

	return !nr_clients;
}

int fio_start_client(struct fio_client *client)
{
	dprint(FD_NET, "client: start %s\n", client->hostname);
	return fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_RUN, 0, NULL);
}

int fio_start_all_clients(void)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;
	int ret;

	dprint(FD_NET, "client: start all\n");

	fio_client_json_init();

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		ret = fio_start_client(client);
		if (ret) {
			remove_client(client);
			continue;
		}
	}

	return flist_empty(&client_list);
}

static int __fio_client_send_remote_ini(struct fio_client *client,
					const char *filename)
{
	struct cmd_load_file_pdu *pdu;
	size_t p_size;
	int ret;

	dprint(FD_NET, "send remote ini %s to %s\n", filename, client->hostname);

	p_size = sizeof(*pdu) + strlen(filename) + 1;
	pdu = malloc(p_size);
	memset(pdu, 0, p_size);
	pdu->name_len = strlen(filename);
	strcpy((char *) pdu->file, filename);
	pdu->client_type = cpu_to_le16((uint16_t) client->type);

	client->sent_job = 1;
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_LOAD_FILE, pdu, p_size,NULL, NULL);
	free(pdu);
	return ret;
}

/*
 * Send file contents to server backend. We could use sendfile(), but to remain
 * more portable lets just read/write the darn thing.
 */
static int __fio_client_send_local_ini(struct fio_client *client,
				       const char *filename)
{
	struct cmd_job_pdu *pdu;
	size_t p_size;
	struct stat sb;
	char *p;
	void *buf;
	off_t len;
	int fd, ret;

	dprint(FD_NET, "send ini %s to %s\n", filename, client->hostname);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		log_err("fio: job file <%s> open: %s\n", filename, strerror(errno));
		return ret;
	}

	if (fstat(fd, &sb) < 0) {
		ret = -errno;
		log_err("fio: job file stat: %s\n", strerror(errno));
		close(fd);
		return ret;
	}

	p_size = sb.st_size + sizeof(*pdu);
	pdu = malloc(p_size);
	buf = pdu->buf;

	len = sb.st_size;
	p = buf;
	if (read_data(fd, p, len)) {
		log_err("fio: failed reading job file %s\n", filename);
		close(fd);
		free(pdu);
		return 1;
	}

	pdu->buf_len = __cpu_to_le32(sb.st_size);
	pdu->client_type = cpu_to_le32(client->type);

	client->sent_job = 1;
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOB, pdu, p_size, NULL, NULL);
	free(pdu);
	close(fd);
	return ret;
}

int fio_client_send_ini(struct fio_client *client, const char *filename,
			bool remote)
{
	int ret;

	if (!remote)
		ret = __fio_client_send_local_ini(client, filename);
	else
		ret = __fio_client_send_remote_ini(client, filename);

	if (!ret)
		client->sent_job = 1;

	return ret;
}

static int fio_client_send_cf(struct fio_client *client,
			      struct client_file *cf)
{
	return fio_client_send_ini(client, cf->file, cf->remote);
}

int fio_clients_send_ini(const char *filename)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;

	flist_for_each_safe(entry, tmp, &client_list) {
		bool failed = false;

		client = flist_entry(entry, struct fio_client, list);

		if (client->nr_files) {
			int i;

			for (i = 0; i < client->nr_files; i++) {
				struct client_file *cf;

				cf = &client->files[i];

				if (fio_client_send_cf(client, cf)) {
					failed = true;
					remove_client(client);
					break;
				}
			}
		}
		if (client->sent_job || failed)
			continue;
		if (!filename || fio_client_send_ini(client, filename, 0))
			remove_client(client);
	}

	return !nr_clients;
}

int fio_client_update_options(struct fio_client *client,
			      struct thread_options *o, uint64_t *tag)
{
	struct cmd_add_job_pdu pdu;

	pdu.thread_number = cpu_to_le32(client->thread_number);
	pdu.groupid = cpu_to_le32(client->groupid);
	convert_thread_options_to_net(&pdu.top, o);

	return fio_net_send_cmd(client->fd, FIO_NET_CMD_UPDATE_JOB, &pdu, sizeof(pdu), tag, &client->cmd_list);
}

static void convert_io_stat(struct io_stat *dst, struct io_stat *src)
{
	dst->max_val	= le64_to_cpu(src->max_val);
	dst->min_val	= le64_to_cpu(src->min_val);
	dst->samples	= le64_to_cpu(src->samples);

	/*
	 * Floats arrive as IEEE 754 encoded uint64_t, convert back to double
	 */
	dst->mean.u.f	= fio_uint64_to_double(le64_to_cpu(dst->mean.u.i));
	dst->S.u.f	= fio_uint64_to_double(le64_to_cpu(dst->S.u.i));
}

static void convert_ts(struct thread_stat *dst, struct thread_stat *src)
{
	int i, j;

	dst->error		= le32_to_cpu(src->error);
	dst->thread_number	= le32_to_cpu(src->thread_number);
	dst->groupid		= le32_to_cpu(src->groupid);
	dst->pid		= le32_to_cpu(src->pid);
	dst->members		= le32_to_cpu(src->members);
	dst->unified_rw_rep	= le32_to_cpu(src->unified_rw_rep);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		convert_io_stat(&dst->clat_stat[i], &src->clat_stat[i]);
		convert_io_stat(&dst->slat_stat[i], &src->slat_stat[i]);
		convert_io_stat(&dst->lat_stat[i], &src->lat_stat[i]);
		convert_io_stat(&dst->bw_stat[i], &src->bw_stat[i]);
	}

	dst->usr_time		= le64_to_cpu(src->usr_time);
	dst->sys_time		= le64_to_cpu(src->sys_time);
	dst->ctx		= le64_to_cpu(src->ctx);
	dst->minf		= le64_to_cpu(src->minf);
	dst->majf		= le64_to_cpu(src->majf);
	dst->clat_percentiles	= le64_to_cpu(src->clat_percentiles);
	dst->percentile_precision = le64_to_cpu(src->percentile_precision);

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		fio_fp64_t *fps = &src->percentile_list[i];
		fio_fp64_t *fpd = &dst->percentile_list[i];

		fpd->u.f = fio_uint64_to_double(le64_to_cpu(fps->u.i));
	}

	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		dst->io_u_map[i]	= le32_to_cpu(src->io_u_map[i]);
		dst->io_u_submit[i]	= le32_to_cpu(src->io_u_submit[i]);
		dst->io_u_complete[i]	= le32_to_cpu(src->io_u_complete[i]);
	}

	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++) {
		dst->io_u_lat_u[i]	= le32_to_cpu(src->io_u_lat_u[i]);
		dst->io_u_lat_m[i]	= le32_to_cpu(src->io_u_lat_m[i]);
	}

	for (i = 0; i < DDIR_RWDIR_CNT; i++)
		for (j = 0; j < FIO_IO_U_PLAT_NR; j++)
			dst->io_u_plat[i][j] = le32_to_cpu(src->io_u_plat[i][j]);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		dst->total_io_u[i]	= le64_to_cpu(src->total_io_u[i]);
		dst->short_io_u[i]	= le64_to_cpu(src->short_io_u[i]);
		dst->drop_io_u[i]	= le64_to_cpu(src->drop_io_u[i]);
	}

	dst->total_submit	= le64_to_cpu(src->total_submit);
	dst->total_complete	= le64_to_cpu(src->total_complete);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		dst->io_bytes[i]	= le64_to_cpu(src->io_bytes[i]);
		dst->runtime[i]		= le64_to_cpu(src->runtime[i]);
	}

	dst->total_run_time	= le64_to_cpu(src->total_run_time);
	dst->continue_on_error	= le16_to_cpu(src->continue_on_error);
	dst->total_err_count	= le64_to_cpu(src->total_err_count);
	dst->first_error	= le32_to_cpu(src->first_error);
	dst->kb_base		= le32_to_cpu(src->kb_base);
	dst->unit_base		= le32_to_cpu(src->unit_base);

	dst->latency_depth	= le32_to_cpu(src->latency_depth);
	dst->latency_target	= le64_to_cpu(src->latency_target);
	dst->latency_window	= le64_to_cpu(src->latency_window);
	dst->latency_percentile.u.f = fio_uint64_to_double(le64_to_cpu(src->latency_percentile.u.i));

	dst->nr_block_infos	= le64_to_cpu(src->nr_block_infos);
	for (i = 0; i < dst->nr_block_infos; i++)
		dst->block_infos[i] = le32_to_cpu(src->block_infos[i]);
}

static void convert_gs(struct group_run_stats *dst, struct group_run_stats *src)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		dst->max_run[i]		= le64_to_cpu(src->max_run[i]);
		dst->min_run[i]		= le64_to_cpu(src->min_run[i]);
		dst->max_bw[i]		= le64_to_cpu(src->max_bw[i]);
		dst->min_bw[i]		= le64_to_cpu(src->min_bw[i]);
		dst->io_kb[i]		= le64_to_cpu(src->io_kb[i]);
		dst->agg[i]		= le64_to_cpu(src->agg[i]);
	}

	dst->kb_base	= le32_to_cpu(src->kb_base);
	dst->unit_base	= le32_to_cpu(src->unit_base);
	dst->groupid	= le32_to_cpu(src->groupid);
	dst->unified_rw_rep	= le32_to_cpu(src->unified_rw_rep);
}

static void json_object_add_client_info(struct json_object *obj,
					struct fio_client *client)
{
	const char *hostname = client->hostname ? client->hostname : "";

	json_object_add_value_string(obj, "hostname", hostname);
	json_object_add_value_int(obj, "port", client->port);
}

static void handle_ts(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;
	struct flist_head *opt_list = NULL;
	struct json_object *tsobj;

	if (client->opt_lists && p->ts.thread_number <= client->jobs)
		opt_list = &client->opt_lists[p->ts.thread_number - 1];

	tsobj = show_thread_status(&p->ts, &p->rs, opt_list, NULL);
	client->did_stat = 1;
	if (tsobj) {
		json_object_add_client_info(tsobj, client);
		json_array_add_value_object(clients_array, tsobj);
	}

	if (sum_stat_clients <= 1)
		return;

	sum_thread_stats(&client_ts, &p->ts, sum_stat_nr == 1);
	sum_group_stats(&client_gs, &p->rs);

	client_ts.members++;
	client_ts.thread_number = p->ts.thread_number;
	client_ts.groupid = p->ts.groupid;
	client_ts.unified_rw_rep = p->ts.unified_rw_rep;

	if (++sum_stat_nr == sum_stat_clients) {
		strcpy(client_ts.name, "All clients");
		tsobj = show_thread_status(&client_ts, &client_gs, NULL, NULL);
		if (tsobj) {
			json_object_add_client_info(tsobj, client);
			json_array_add_value_object(clients_array, tsobj);
		}
	}
}

static void handle_gs(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct group_run_stats *gs = (struct group_run_stats *) cmd->payload;

	if (output_format & FIO_OUTPUT_NORMAL)
		show_group_stats(gs, NULL);
}

static void handle_job_opt(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_job_option *pdu = (struct cmd_job_option *) cmd->payload;
	struct print_option *p;

	if (!job_opt_object)
		return;

	pdu->global = le16_to_cpu(pdu->global);
	pdu->truncated = le16_to_cpu(pdu->truncated);
	pdu->groupid = le32_to_cpu(pdu->groupid);

	p = malloc(sizeof(*p));
	p->name = strdup((char *) pdu->name);
	if (pdu->value[0] != '\0')
		p->value = strdup((char *) pdu->value);
	else
		p->value = NULL;

	if (pdu->global) {
		const char *pos = "";

		if (p->value)
			pos = p->value;

		json_object_add_value_string(job_opt_object, p->name, pos);
	} else if (client->opt_lists) {
		struct flist_head *opt_list = &client->opt_lists[pdu->groupid];

		flist_add_tail(&p->list, opt_list);
	}
}

static void handle_text(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_text_pdu *pdu = (struct cmd_text_pdu *) cmd->payload;
	const char *buf = (const char *) pdu->buf;
	const char *name;
	int fio_unused ret;

	name = client->name ? client->name : client->hostname;

	if (!client->skip_newline)
		fprintf(f_out, "<%s> ", name);
	ret = fwrite(buf, pdu->buf_len, 1, f_out);
	fflush(f_out);
	client->skip_newline = strchr(buf, '\n') == NULL;
}

static void convert_agg(struct disk_util_agg *agg)
{
	int i;

	for (i = 0; i < 2; i++) {
		agg->ios[i]	= le64_to_cpu(agg->ios[i]);
		agg->merges[i]	= le64_to_cpu(agg->merges[i]);
		agg->sectors[i]	= le64_to_cpu(agg->sectors[i]);
		agg->ticks[i]	= le64_to_cpu(agg->ticks[i]);
	}

	agg->io_ticks		= le64_to_cpu(agg->io_ticks);
	agg->time_in_queue	= le64_to_cpu(agg->time_in_queue);
	agg->slavecount		= le32_to_cpu(agg->slavecount);
	agg->max_util.u.f	= fio_uint64_to_double(le64_to_cpu(agg->max_util.u.i));
}

static void convert_dus(struct disk_util_stat *dus)
{
	int i;

	for (i = 0; i < 2; i++) {
		dus->s.ios[i]		= le64_to_cpu(dus->s.ios[i]);
		dus->s.merges[i]	= le64_to_cpu(dus->s.merges[i]);
		dus->s.sectors[i]	= le64_to_cpu(dus->s.sectors[i]);
		dus->s.ticks[i]		= le64_to_cpu(dus->s.ticks[i]);
	}

	dus->s.io_ticks		= le64_to_cpu(dus->s.io_ticks);
	dus->s.time_in_queue	= le64_to_cpu(dus->s.time_in_queue);
	dus->s.msec		= le64_to_cpu(dus->s.msec);
}

static void handle_du(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_du_pdu *du = (struct cmd_du_pdu *) cmd->payload;

	if (!client->disk_stats_shown) {
		client->disk_stats_shown = 1;
		log_info("\nDisk stats (read/write):\n");
	}

	if (output_format & FIO_OUTPUT_JSON) {
		struct json_object *duobj;
		json_array_add_disk_util(&du->dus, &du->agg, du_array);
		duobj = json_array_last_value_object(du_array);
		json_object_add_client_info(duobj, client);
	}
	if (output_format & FIO_OUTPUT_TERSE)
		print_disk_util(&du->dus, &du->agg, 1, NULL);
	if (output_format & FIO_OUTPUT_NORMAL)
		print_disk_util(&du->dus, &du->agg, 0, NULL);
}

static void convert_jobs_eta(struct jobs_eta *je)
{
	int i;

	je->nr_running		= le32_to_cpu(je->nr_running);
	je->nr_ramp		= le32_to_cpu(je->nr_ramp);
	je->nr_pending		= le32_to_cpu(je->nr_pending);
	je->nr_setting_up	= le32_to_cpu(je->nr_setting_up);
	je->files_open		= le32_to_cpu(je->files_open);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		je->m_rate[i]	= le32_to_cpu(je->m_rate[i]);
		je->t_rate[i]	= le32_to_cpu(je->t_rate[i]);
		je->m_iops[i]	= le32_to_cpu(je->m_iops[i]);
		je->t_iops[i]	= le32_to_cpu(je->t_iops[i]);
		je->rate[i]	= le32_to_cpu(je->rate[i]);
		je->iops[i]	= le32_to_cpu(je->iops[i]);
	}

	je->elapsed_sec		= le64_to_cpu(je->elapsed_sec);
	je->eta_sec		= le64_to_cpu(je->eta_sec);
	je->nr_threads		= le32_to_cpu(je->nr_threads);
	je->is_pow2		= le32_to_cpu(je->is_pow2);
	je->unit_base		= le32_to_cpu(je->unit_base);
}

void fio_client_sum_jobs_eta(struct jobs_eta *dst, struct jobs_eta *je)
{
	int i;

	dst->nr_running		+= je->nr_running;
	dst->nr_ramp		+= je->nr_ramp;
	dst->nr_pending		+= je->nr_pending;
	dst->nr_setting_up	+= je->nr_setting_up;
	dst->files_open		+= je->files_open;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		dst->m_rate[i]	+= je->m_rate[i];
		dst->t_rate[i]	+= je->t_rate[i];
		dst->m_iops[i]	+= je->m_iops[i];
		dst->t_iops[i]	+= je->t_iops[i];
		dst->rate[i]	+= je->rate[i];
		dst->iops[i]	+= je->iops[i];
	}

	dst->elapsed_sec	+= je->elapsed_sec;

	if (je->eta_sec > dst->eta_sec)
		dst->eta_sec = je->eta_sec;

	dst->nr_threads		+= je->nr_threads;

	/*
	 * This wont be correct for multiple strings, but at least it
	 * works for the basic cases.
	 */
	strcpy((char *) dst->run_str, (char *) je->run_str);
}

static bool remove_reply_cmd(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct fio_net_cmd_reply *reply = NULL;
	struct flist_head *entry;

	flist_for_each(entry, &client->cmd_list) {
		reply = flist_entry(entry, struct fio_net_cmd_reply, list);

		if (cmd->tag == (uintptr_t) reply)
			break;

		reply = NULL;
	}

	if (!reply) {
		log_err("fio: client: unable to find matching tag (%llx)\n", (unsigned long long) cmd->tag);
		return false;
	}

	flist_del(&reply->list);
	cmd->tag = reply->saved_tag;
	free(reply);
	return true;
}

int fio_client_wait_for_reply(struct fio_client *client, uint64_t tag)
{
	do {
		struct fio_net_cmd_reply *reply = NULL;
		struct flist_head *entry;

		flist_for_each(entry, &client->cmd_list) {
			reply = flist_entry(entry, struct fio_net_cmd_reply, list);

			if (tag == (uintptr_t) reply)
				break;

			reply = NULL;
		}

		if (!reply)
			break;

		usleep(1000);
	} while (1);

	return 0;
}

static void handle_eta(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct jobs_eta *je = (struct jobs_eta *) cmd->payload;
	struct client_eta *eta = (struct client_eta *) (uintptr_t) cmd->tag;

	dprint(FD_NET, "client: got eta tag %p, %d\n", eta, eta->pending);

	assert(client->eta_in_flight == eta);

	client->eta_in_flight = NULL;
	flist_del_init(&client->eta_list);
	client->eta_timeouts = 0;

	if (client->ops->jobs_eta)
		client->ops->jobs_eta(client, je);

	fio_client_sum_jobs_eta(&eta->eta, je);
	fio_client_dec_jobs_eta(eta, client->ops->eta);
}

static void client_flush_hist_samples(FILE *f, int hist_coarseness, void *samples,
				      uint64_t sample_size)
{
	struct io_sample *s;
	int log_offset;
	uint64_t i, j, nr_samples;
	struct io_u_plat_entry *entry;
	unsigned int *io_u_plat;

	int stride = 1 << hist_coarseness;

	if (!sample_size)
		return;

	s = __get_sample(samples, 0, 0);
	log_offset = (s->__ddir & LOG_OFFSET_SAMPLE_BIT) != 0;

	nr_samples = sample_size / __log_entry_sz(log_offset);

	for (i = 0; i < nr_samples; i++) {

		s = (struct io_sample *)((char *)__get_sample(samples, log_offset, i) +
			i * sizeof(struct io_u_plat_entry));

		entry = s->plat_entry;
		io_u_plat = entry->io_u_plat;

		fprintf(f, "%lu, %u, %u, ", (unsigned long) s->time,
						io_sample_ddir(s), s->bs);
		for (j = 0; j < FIO_IO_U_PLAT_NR - stride; j += stride) {
			fprintf(f, "%lu, ", hist_sum(j, stride, io_u_plat, NULL));
		}
		fprintf(f, "%lu\n", (unsigned long)
			hist_sum(FIO_IO_U_PLAT_NR - stride, stride, io_u_plat, NULL));

	}
}

static int fio_client_handle_iolog(struct fio_client *client,
				   struct fio_net_cmd *cmd)
{
	struct cmd_iolog_pdu *pdu;
	bool store_direct;
	char *log_pathname;

	pdu = convert_iolog(cmd, &store_direct);
	if (!pdu) {
		log_err("fio: failed converting IO log\n");
		return 1;
	}

        /* allocate buffer big enough for next sprintf() call */
	log_pathname = malloc( 10 + 
			strlen((char * )pdu->name) + 
			strlen(client->hostname));
	if (!log_pathname) {
		log_err("fio: memory allocation of unique pathname failed");
		return -1;
	}
	/* generate a unique pathname for the log file using hostname */
	sprintf(log_pathname, "%s.%s", pdu->name, client->hostname);

	if (store_direct) {
		ssize_t ret;
		size_t sz;
		int fd;

		fd = open((const char *) log_pathname,
				O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			log_err("fio: open log %s: %s\n", 
				log_pathname, strerror(errno));
			return 1;
		}

		sz = cmd->pdu_len - sizeof(*pdu);
		ret = write(fd, pdu->samples, sz);
		close(fd);

		if (ret != sz) {
			log_err("fio: short write on compressed log\n");
			return 1;
		}

		return 0;
	} else {
		FILE *f;
		f = fopen((const char *) log_pathname, "w");
		if (!f) {
			log_err("fio: fopen log %s : %s\n", 
				log_pathname, strerror(errno));
			return 1;
		}

		if (pdu->log_type == IO_LOG_TYPE_HIST) {
			client_flush_hist_samples(f, pdu->log_hist_coarseness, pdu->samples,
					   pdu->nr_samples * sizeof(struct io_sample));
		} else {
			flush_samples(f, pdu->samples,
					pdu->nr_samples * sizeof(struct io_sample));
		}
		fclose(f);
		return 0;
	}
}

static void handle_probe(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_reply_pdu *probe = (struct cmd_probe_reply_pdu *) cmd->payload;
	const char *os, *arch;
	char bit[16];

	os = fio_get_os_string(probe->os);
	if (!os)
		os = "unknown";

	arch = fio_get_arch_string(probe->arch);
	if (!arch)
		os = "unknown";

	sprintf(bit, "%d-bit", probe->bpp * 8);
	probe->flags = le64_to_cpu(probe->flags);

	log_info("hostname=%s, be=%u, %s, os=%s, arch=%s, fio=%s, flags=%lx\n",
		probe->hostname, probe->bigendian, bit, os, arch,
		probe->fio_version, (unsigned long) probe->flags);

	if (!client->name)
		client->name = strdup((char *) probe->hostname);
}

static void handle_start(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_start_pdu *pdu = (struct cmd_start_pdu *) cmd->payload;

	client->state = Client_started;
	client->jobs = le32_to_cpu(pdu->jobs);
	client->nr_stat = le32_to_cpu(pdu->stat_outputs);

	if (client->jobs) {
		int i;

		if (client->opt_lists)
			free(client->opt_lists);

		client->opt_lists = malloc(client->jobs * sizeof(struct flist_head));
		for (i = 0; i < client->jobs; i++)
			INIT_FLIST_HEAD(&client->opt_lists[i]);
	}

	sum_stat_clients += client->nr_stat;
}

static void handle_stop(struct fio_client *client, struct fio_net_cmd *cmd)
{
	if (client->error)
		log_info("client <%s>: exited with error %d\n", client->hostname, client->error);
}

static void convert_stop(struct fio_net_cmd *cmd)
{
	struct cmd_end_pdu *pdu = (struct cmd_end_pdu *) cmd->payload;

	pdu->error = le32_to_cpu(pdu->error);
}

static void convert_text(struct fio_net_cmd *cmd)
{
	struct cmd_text_pdu *pdu = (struct cmd_text_pdu *) cmd->payload;

	pdu->level	= le32_to_cpu(pdu->level);
	pdu->buf_len	= le32_to_cpu(pdu->buf_len);
	pdu->log_sec	= le64_to_cpu(pdu->log_sec);
	pdu->log_usec	= le64_to_cpu(pdu->log_usec);
}

static struct cmd_iolog_pdu *convert_iolog_gz(struct fio_net_cmd *cmd,
					      struct cmd_iolog_pdu *pdu)
{
#ifdef CONFIG_ZLIB
	struct cmd_iolog_pdu *ret;
	z_stream stream;
	uint32_t nr_samples;
	size_t total;
	void *p;

	stream.zalloc = Z_NULL;
	stream.zfree = Z_NULL;
	stream.opaque = Z_NULL;
	stream.avail_in = 0;
	stream.next_in = Z_NULL;

	if (inflateInit(&stream) != Z_OK)
		return NULL;

	/*
	 * Get header first, it's not compressed
	 */
	nr_samples = le64_to_cpu(pdu->nr_samples);

	if (pdu->log_type == IO_LOG_TYPE_HIST)
		total = nr_samples * (__log_entry_sz(le32_to_cpu(pdu->log_offset)) +
					sizeof(struct io_u_plat_entry));
	else
		total = nr_samples * __log_entry_sz(le32_to_cpu(pdu->log_offset));
	ret = malloc(total + sizeof(*pdu));
	ret->nr_samples = nr_samples;

	memcpy(ret, pdu, sizeof(*pdu));

	p = (void *) ret + sizeof(*pdu);

	stream.avail_in = cmd->pdu_len - sizeof(*pdu);
	stream.next_in = (void *) pdu + sizeof(*pdu);
	while (stream.avail_in) {
		unsigned int this_chunk = 65536;
		unsigned int this_len;
		int err;

		if (this_chunk > total)
			this_chunk = total;

		stream.avail_out = this_chunk;
		stream.next_out = p;
		err = inflate(&stream, Z_NO_FLUSH);
		/* may be Z_OK, or Z_STREAM_END */
		if (err < 0) {
			log_err("fio: inflate error %d\n", err);
			free(ret);
			ret = NULL;
			goto err;
		}

		this_len = this_chunk - stream.avail_out;
		p += this_len;
		total -= this_len;
	}

err:
	inflateEnd(&stream);
	return ret;
#else
	return NULL;
#endif
}

/*
 * This has been compressed on the server side, since it can be big.
 * Uncompress here.
 */
static struct cmd_iolog_pdu *convert_iolog(struct fio_net_cmd *cmd,
					   bool *store_direct)
{
	struct cmd_iolog_pdu *pdu = (struct cmd_iolog_pdu *) cmd->payload;
	struct cmd_iolog_pdu *ret;
	uint64_t i;
	int compressed;
	void *samples;

	*store_direct = false;

	/*
	 * Convert if compressed and we support it. If it's not
	 * compressed, we need not do anything.
	 */
	compressed = le32_to_cpu(pdu->compressed);
	if (compressed == XMIT_COMPRESSED) {
#ifndef CONFIG_ZLIB
		log_err("fio: server sent compressed data by mistake\n");
		return NULL;
#endif
		ret = convert_iolog_gz(cmd, pdu);
		if (!ret) {
			log_err("fio: failed decompressing log\n");
			return NULL;
		}
	} else if (compressed == STORE_COMPRESSED) {
		*store_direct = true;
		ret = pdu;
	} else
		ret = pdu;

	ret->nr_samples		= le64_to_cpu(ret->nr_samples);
	ret->thread_number	= le32_to_cpu(ret->thread_number);
	ret->log_type		= le32_to_cpu(ret->log_type);
	ret->compressed		= le32_to_cpu(ret->compressed);
	ret->log_offset		= le32_to_cpu(ret->log_offset);
	ret->log_hist_coarseness = le32_to_cpu(ret->log_hist_coarseness);

	if (*store_direct)
		return ret;

	samples = &ret->samples[0];
	for (i = 0; i < ret->nr_samples; i++) {
		struct io_sample *s;

		s = __get_sample(samples, ret->log_offset, i);
		if (ret->log_type == IO_LOG_TYPE_HIST)
			s = (struct io_sample *)((void *)s + sizeof(struct io_u_plat_entry) * i);

		s->time		= le64_to_cpu(s->time);
		s->val		= le64_to_cpu(s->val);
		s->__ddir	= le32_to_cpu(s->__ddir);
		s->bs		= le32_to_cpu(s->bs);

		if (ret->log_offset) {
			struct io_sample_offset *so = (void *) s;

			so->offset = le64_to_cpu(so->offset);
		}

		if (ret->log_type == IO_LOG_TYPE_HIST) {
			s->plat_entry = (struct io_u_plat_entry *)(((void *)s) + sizeof(*s));
			s->plat_entry->list.next = NULL;
			s->plat_entry->list.prev = NULL;
		}
	}

	return ret;
}

static void sendfile_reply(int fd, struct cmd_sendfile_reply *rep,
			   size_t size, uint64_t tag)
{
	rep->error = cpu_to_le32(rep->error);
	fio_net_send_cmd(fd, FIO_NET_CMD_SENDFILE, rep, size, &tag, NULL);
}

static int fio_send_file(struct fio_client *client, struct cmd_sendfile *pdu,
			 uint64_t tag)
{
	struct cmd_sendfile_reply *rep;
	struct stat sb;
	size_t size;
	int fd;

	size = sizeof(*rep);
	rep = malloc(size);

	if (stat((char *)pdu->path, &sb) < 0) {
fail:
		rep->error = errno;
		sendfile_reply(client->fd, rep, size, tag);
		free(rep);
		return 1;
	}

	size += sb.st_size;
	rep = realloc(rep, size);
	rep->size = cpu_to_le32((uint32_t) sb.st_size);

	fd = open((char *)pdu->path, O_RDONLY);
	if (fd == -1 )
		goto fail;

	rep->error = read_data(fd, &rep->data, sb.st_size);
	sendfile_reply(client->fd, rep, size, tag);
	free(rep);
	close(fd);
	return 0;
}

int fio_handle_client(struct fio_client *client)
{
	struct client_ops *ops = client->ops;
	struct fio_net_cmd *cmd;

	dprint(FD_NET, "client: handle %s\n", client->hostname);

	cmd = fio_net_recv_cmd(client->fd, true);
	if (!cmd)
		return 0;

	dprint(FD_NET, "client: got cmd op %s from %s (pdu=%u)\n",
		fio_server_op(cmd->opcode), client->hostname, cmd->pdu_len);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
		if (ops->quit)
			ops->quit(client, cmd);
		remove_client(client);
		break;
	case FIO_NET_CMD_TEXT:
		convert_text(cmd);
		ops->text(client, cmd);
		break;
	case FIO_NET_CMD_DU: {
		struct cmd_du_pdu *du = (struct cmd_du_pdu *) cmd->payload;

		convert_dus(&du->dus);
		convert_agg(&du->agg);

		ops->disk_util(client, cmd);
		break;
		}
	case FIO_NET_CMD_TS: {
		struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;

		convert_ts(&p->ts, &p->ts);
		convert_gs(&p->rs, &p->rs);

		ops->thread_status(client, cmd);
		break;
		}
	case FIO_NET_CMD_GS: {
		struct group_run_stats *gs = (struct group_run_stats *) cmd->payload;

		convert_gs(gs, gs);

		ops->group_stats(client, cmd);
		break;
		}
	case FIO_NET_CMD_ETA: {
		struct jobs_eta *je = (struct jobs_eta *) cmd->payload;

		if (!remove_reply_cmd(client, cmd))
			break;
		convert_jobs_eta(je);
		handle_eta(client, cmd);
		break;
		}
	case FIO_NET_CMD_PROBE:
		remove_reply_cmd(client, cmd);
		ops->probe(client, cmd);
		break;
	case FIO_NET_CMD_SERVER_START:
		client->state = Client_running;
		if (ops->job_start)
			ops->job_start(client, cmd);
		break;
	case FIO_NET_CMD_START: {
		struct cmd_start_pdu *pdu = (struct cmd_start_pdu *) cmd->payload;

		pdu->jobs = le32_to_cpu(pdu->jobs);
		ops->start(client, cmd);
		break;
		}
	case FIO_NET_CMD_STOP: {
		struct cmd_end_pdu *pdu = (struct cmd_end_pdu *) cmd->payload;

		convert_stop(cmd);
		client->state = Client_stopped;
		client->error = le32_to_cpu(pdu->error);
		client->signal = le32_to_cpu(pdu->signal);
		ops->stop(client, cmd);
		break;
		}
	case FIO_NET_CMD_ADD_JOB: {
		struct cmd_add_job_pdu *pdu = (struct cmd_add_job_pdu *) cmd->payload;

		client->thread_number = le32_to_cpu(pdu->thread_number);
		client->groupid = le32_to_cpu(pdu->groupid);

		if (ops->add_job)
			ops->add_job(client, cmd);
		break;
		}
	case FIO_NET_CMD_IOLOG:
		fio_client_handle_iolog(client, cmd);
		break;
	case FIO_NET_CMD_UPDATE_JOB:
		ops->update_job(client, cmd);
		remove_reply_cmd(client, cmd);
		break;
	case FIO_NET_CMD_VTRIGGER: {
		struct all_io_list *pdu = (struct all_io_list *) cmd->payload;
		char buf[128];
		int off = 0;

		if (aux_path) {
			strcpy(buf, aux_path);
			off = strlen(buf);
		}

		__verify_save_state(pdu, server_name(client, &buf[off], sizeof(buf) - off));
		exec_trigger(trigger_cmd);
		break;
		}
	case FIO_NET_CMD_SENDFILE: {
		struct cmd_sendfile *pdu = (struct cmd_sendfile *) cmd->payload;
		fio_send_file(client, pdu, cmd->tag);
		break;
		}
	case FIO_NET_CMD_JOB_OPT: {
		handle_job_opt(client, cmd);
		break;
	}
	default:
		log_err("fio: unknown client op: %s\n", fio_server_op(cmd->opcode));
		break;
	}

	free(cmd);
	return 1;
}

int fio_clients_send_trigger(const char *cmd)
{
	struct flist_head *entry;
	struct fio_client *client;
	size_t slen;

	dprint(FD_NET, "client: send vtrigger: %s\n", cmd);

	if (!cmd)
		slen = 0;
	else
		slen = strlen(cmd);

	flist_for_each(entry, &client_list) {
		struct cmd_vtrigger_pdu *pdu;

		client = flist_entry(entry, struct fio_client, list);

		pdu = malloc(sizeof(*pdu) + slen);
		pdu->len = cpu_to_le16((uint16_t) slen);
		if (slen)
			memcpy(pdu->cmd, cmd, slen);
		fio_net_send_cmd(client->fd, FIO_NET_CMD_VTRIGGER, pdu,
					sizeof(*pdu) + slen, NULL, NULL);
		free(pdu);
	}

	return 0;
}

static void request_client_etas(struct client_ops *ops)
{
	struct fio_client *client;
	struct flist_head *entry;
	struct client_eta *eta;
	int skipped = 0;

	dprint(FD_NET, "client: request eta (%d)\n", nr_clients);

	eta = calloc(1, sizeof(*eta) + __THREAD_RUNSTR_SZ(REAL_MAX_JOBS));
	eta->pending = nr_clients;

	flist_for_each(entry, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (!flist_empty(&client->eta_list)) {
			skipped++;
			continue;
		}
		if (client->state != Client_running)
			continue;

		assert(!client->eta_in_flight);
		flist_add_tail(&client->eta_list, &eta_list);
		client->eta_in_flight = eta;
		fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_SEND_ETA,
					(uintptr_t) eta, &client->cmd_list);
	}

	while (skipped--) {
		if (!fio_client_dec_jobs_eta(eta, ops->eta))
			break;
	}

	dprint(FD_NET, "client: requested eta tag %p\n", eta);
}

/*
 * A single SEND_ETA timeout isn't fatal. Attempt to recover.
 */
static int handle_cmd_timeout(struct fio_client *client,
			      struct fio_net_cmd_reply *reply)
{
	flist_del(&reply->list);
	free(reply);

	if (reply->opcode != FIO_NET_CMD_SEND_ETA)
		return 1;

	log_info("client <%s>: timeout on SEND_ETA\n", client->hostname);

	flist_del_init(&client->eta_list);
	if (client->eta_in_flight) {
		fio_client_dec_jobs_eta(client->eta_in_flight, client->ops->eta);
		client->eta_in_flight = NULL;
	}

	/*
	 * If we fail 5 in a row, give up...
	 */
	if (client->eta_timeouts++ > 5)
		return 1;

	return 0;
}

static int client_check_cmd_timeout(struct fio_client *client,
				    struct timeval *now)
{
	struct fio_net_cmd_reply *reply;
	struct flist_head *entry, *tmp;
	int ret = 0;

	flist_for_each_safe(entry, tmp, &client->cmd_list) {
		reply = flist_entry(entry, struct fio_net_cmd_reply, list);

		if (mtime_since(&reply->tv, now) < FIO_NET_CLIENT_TIMEOUT)
			continue;

		if (!handle_cmd_timeout(client, reply))
			continue;

		log_err("fio: client %s, timeout on cmd %s\n", client->hostname,
						fio_server_op(reply->opcode));
		ret = 1;
	}

	return flist_empty(&client->cmd_list) && ret;
}

static int fio_check_clients_timed_out(void)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;
	struct timeval tv;
	int ret = 0;

	fio_gettime(&tv, NULL);

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (flist_empty(&client->cmd_list))
			continue;

		if (!client_check_cmd_timeout(client, &tv))
			continue;

		if (client->ops->timed_out)
			client->ops->timed_out(client);
		else
			log_err("fio: client %s timed out\n", client->hostname);

		client->error = ETIMEDOUT;
		remove_client(client);
		ret = 1;
	}

	return ret;
}

int fio_handle_clients(struct client_ops *ops)
{
	struct pollfd *pfds;
	int i, ret = 0, retval = 0;

	fio_gettime(&eta_tv, NULL);

	pfds = malloc(nr_clients * sizeof(struct pollfd));

	init_thread_stat(&client_ts);
	init_group_run_stat(&client_gs);

	while (!exit_backend && nr_clients) {
		struct flist_head *entry, *tmp;
		struct fio_client *client;

		i = 0;
		flist_for_each_safe(entry, tmp, &client_list) {
			client = flist_entry(entry, struct fio_client, list);

			if (!client->sent_job && !client->ops->stay_connected &&
			    flist_empty(&client->cmd_list)) {
				remove_client(client);
				continue;
			}

			pfds[i].fd = client->fd;
			pfds[i].events = POLLIN;
			i++;
		}

		if (!nr_clients)
			break;

		assert(i == nr_clients);

		do {
			struct timeval tv;
			int timeout;

			fio_gettime(&tv, NULL);
			if (mtime_since(&eta_tv, &tv) >= 900) {
				request_client_etas(ops);
				memcpy(&eta_tv, &tv, sizeof(tv));

				if (fio_check_clients_timed_out())
					break;
			}

			check_trigger_file();

			timeout = min(100u, ops->eta_msec);

			ret = poll(pfds, nr_clients, timeout);
			if (ret < 0) {
				if (errno == EINTR)
					continue;
				log_err("fio: poll clients: %s\n", strerror(errno));
				break;
			} else if (!ret)
				continue;
		} while (ret <= 0);

		for (i = 0; i < nr_clients; i++) {
			if (!(pfds[i].revents & POLLIN))
				continue;

			client = find_client_by_fd(pfds[i].fd);
			if (!client) {
				log_err("fio: unknown client fd %ld\n", (long) pfds[i].fd);
				continue;
			}
			if (!fio_handle_client(client)) {
				log_info("client: host=%s disconnected\n",
						client->hostname);
				remove_client(client);
				retval = 1;
			} else if (client->error)
				retval = 1;
			fio_put_client(client);
		}
	}

	fio_client_json_fini();

	free(pfds);
	return retval || error_clients;
}
