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

#include "fio.h"
#include "server.h"
#include "flist.h"
#include "hash.h"

struct client_eta {
	unsigned int pending;
	struct jobs_eta eta;
};

struct fio_client {
	struct flist_head list;
	struct flist_head hash_list;
	struct flist_head arg_list;
	union {
		struct sockaddr_in addr;
		struct sockaddr_in6 addr6;
		struct sockaddr_un addr_un;
	};
	char *hostname;
	int port;
	int fd;
	unsigned int refs;

	char *name;

	int state;

	int skip_newline;
	int is_sock;
	int disk_stats_shown;
	unsigned int jobs;
	unsigned int nr_stat;
	int error;
	int ipv6;
	int sent_job;
	int did_stat;

	struct flist_head eta_list;
	struct client_eta *eta_in_flight;

	struct flist_head cmd_list;

	uint16_t argc;
	char **argv;

	char **ini_file;
	unsigned int nr_ini_file;
};

static struct timeval eta_tv;

enum {
	Client_created		= 0,
	Client_connected	= 1,
	Client_started		= 2,
	Client_running		= 3,
	Client_stopped		= 4,
	Client_exited		= 5,
};

static FLIST_HEAD(client_list);
static FLIST_HEAD(eta_list);

static FLIST_HEAD(arg_list);

static struct thread_stat client_ts;
static struct group_run_stats client_gs;
static int sum_stat_clients = 0;
static int sum_stat_nr;
static int do_output_all_clients;

#define FIO_CLIENT_HASH_BITS	7
#define FIO_CLIENT_HASH_SZ	(1 << FIO_CLIENT_HASH_BITS)
#define FIO_CLIENT_HASH_MASK	(FIO_CLIENT_HASH_SZ - 1)
static struct flist_head client_hash[FIO_CLIENT_HASH_SZ];

static int handle_client(struct fio_client *client);
static void dec_jobs_eta(struct client_eta *eta);

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

static void remove_client(struct fio_client *client)
{
	assert(client->refs);

	if (--client->refs)
		return;

	dprint(FD_NET, "client: removed <%s>\n", client->hostname);
	flist_del(&client->list);

	fio_client_remove_hash(client);

	if (!flist_empty(&client->eta_list)) {
		flist_del_init(&client->eta_list);
		dec_jobs_eta(client->eta_in_flight);
	}

	free(client->hostname);
	if (client->argv)
		free(client->argv);
	if (client->name)
		free(client->name);
	while (client->nr_ini_file)
		free(client->ini_file[--client->nr_ini_file]);
	if (client->ini_file)
		free(client->ini_file);

	if (!client->did_stat)
		sum_stat_clients -= client->nr_stat;

	free(client);
	nr_clients--;
}

static void put_client(struct fio_client *client)
{
	remove_client(client);
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

void fio_client_add_ini_file(void *cookie, const char *ini_file)
{
	struct fio_client *client = cookie;
	size_t new_size;

	dprint(FD_NET, "client <%s>: add ini %s\n", client->hostname, ini_file);

	new_size = (client->nr_ini_file + 1) * sizeof(char *);
	client->ini_file = realloc(client->ini_file, new_size);
	client->ini_file[client->nr_ini_file] = strdup(ini_file);
	client->nr_ini_file++;
}

int fio_client_add(const char *hostname, void **cookie)
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
	client->refs = 1;

	__fio_client_add_cmd_option(client, "fio");

	flist_add(&client->list, &client_list);
	nr_clients++;
	dprint(FD_NET, "client: added <%s>\n", client->hostname);
	*cookie = client;
	return 0;
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
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	if (connect(fd, addr, socklen) < 0) {
		log_err("fio: connect: %s\n", strerror(errno));
		log_err("fio: failed to connect to %s:%u\n", client->hostname,
								client->port);
		close(fd);
		return -1;
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
	strcpy(addr->sun_path, client->hostname);

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	len = sizeof(addr->sun_family) + strlen(addr->sun_path) + 1;
	if (connect(fd, (struct sockaddr *) addr, len) < 0) {
		log_err("fio: connect; %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	return fd;
}

static int fio_client_connect(struct fio_client *client)
{
	int fd;

	dprint(FD_NET, "client: connect to host %s\n", client->hostname);

	if (client->is_sock)
		fd = fio_client_connect_sock(client);
	else
		fd = fio_client_connect_ip(client);

	dprint(FD_NET, "client: %s connected %d\n", client->hostname, fd);

	if (fd < 0)
		return 1;

	client->fd = fd;
	fio_client_add_hash(client);
	client->state = Client_connected;
	return 0;
}

void fio_clients_terminate(void)
{
	struct flist_head *entry;
	struct fio_client *client;

	dprint(FD_NET, "client: terminate clients\n");

	flist_for_each(entry, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_QUIT, 0, NULL);
	}
}

static void sig_int(int sig)
{
	dprint(FD_NET, "client: got signal %d\n", sig);
	fio_clients_terminate();
}

static void sig_show_status(int sig)
{
	show_running_run_stats();
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

static void probe_client(struct fio_client *client)
{
	dprint(FD_NET, "client: send probe\n");

	fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_PROBE, 0, &client->cmd_list);
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
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOBLINE, pdu, mem, 0);
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
	WSAStartup(MAKEWORD(2,2), &wsd);
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

		probe_client(client);

		if (client->argc > 1)
			send_client_cmd_line(client);
	}

	return !nr_clients;
}

/*
 * Send file contents to server backend. We could use sendfile(), but to remain
 * more portable lets just read/write the darn thing.
 */
static int fio_client_send_ini(struct fio_client *client, const char *filename)
{
	struct stat sb;
	char *p, *buf;
	off_t len;
	int fd, ret;

	dprint(FD_NET, "send ini %s to %s\n", filename, client->hostname);

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		log_err("fio: job file <%s> open: %s\n", filename, strerror(errno));
		return 1;
	}

	if (fstat(fd, &sb) < 0) {
		log_err("fio: job file stat: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	buf = malloc(sb.st_size);

	len = sb.st_size;
	p = buf;
	do {
		ret = read(fd, p, len);
		if (ret > 0) {
			len -= ret;
			if (!len)
				break;
			p += ret;
			continue;
		} else if (!ret)
			break;
		else if (errno == EAGAIN || errno == EINTR)
			continue;
	} while (1);

	if (len) {
		log_err("fio: failed reading job file %s\n", filename);
		close(fd);
		free(buf);
		return 1;
	}

	client->sent_job = 1;
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOB, buf, sb.st_size, 0);
	free(buf);
	close(fd);
	return ret;
}

int fio_clients_send_ini(const char *filename)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (client->nr_ini_file) {
			int i;

			for (i = 0; i < client->nr_ini_file; i++) {
				const char *ini = client->ini_file[i];

				if (fio_client_send_ini(client, ini)) {
					remove_client(client);
					break;
				}
			}
		} else if (!filename || fio_client_send_ini(client, filename))
			remove_client(client);

		client->sent_job = 1;
	}

	return !nr_clients;
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

	dst->error	= le32_to_cpu(src->error);
	dst->groupid	= le32_to_cpu(src->groupid);
	dst->pid	= le32_to_cpu(src->pid);
	dst->members	= le32_to_cpu(src->members);

	for (i = 0; i < 2; i++) {
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

	for (i = 0; i < 2; i++)
		for (j = 0; j < FIO_IO_U_PLAT_NR; j++)
			dst->io_u_plat[i][j] = le32_to_cpu(src->io_u_plat[i][j]);

	for (i = 0; i < 3; i++) {
		dst->total_io_u[i]	= le64_to_cpu(src->total_io_u[i]);
		dst->short_io_u[i]	= le64_to_cpu(src->short_io_u[i]);
	}

	dst->total_submit	= le64_to_cpu(src->total_submit);
	dst->total_complete	= le64_to_cpu(src->total_complete);

	for (i = 0; i < 2; i++) {
		dst->io_bytes[i]	= le64_to_cpu(src->io_bytes[i]);
		dst->runtime[i]		= le64_to_cpu(src->runtime[i]);
	}

	dst->total_run_time	= le64_to_cpu(src->total_run_time);
	dst->continue_on_error	= le16_to_cpu(src->continue_on_error);
	dst->total_err_count	= le64_to_cpu(src->total_err_count);
	dst->first_error	= le32_to_cpu(src->first_error);
	dst->kb_base		= le32_to_cpu(src->kb_base);
}

static void convert_gs(struct group_run_stats *dst, struct group_run_stats *src)
{
	int i;

	for (i = 0; i < 2; i++) {
		dst->max_run[i]		= le64_to_cpu(src->max_run[i]);
		dst->min_run[i]		= le64_to_cpu(src->min_run[i]);
		dst->max_bw[i]		= le64_to_cpu(src->max_bw[i]);
		dst->min_bw[i]		= le64_to_cpu(src->min_bw[i]);
		dst->io_kb[i]		= le64_to_cpu(src->io_kb[i]);
		dst->agg[i]		= le64_to_cpu(src->agg[i]);
	}

	dst->kb_base	= le32_to_cpu(src->kb_base);
	dst->groupid	= le32_to_cpu(src->groupid);
}

static void handle_ts(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;

	convert_ts(&p->ts, &p->ts);
	convert_gs(&p->rs, &p->rs);

	show_thread_status(&p->ts, &p->rs);
	client->did_stat = 1;

	if (!do_output_all_clients)
		return;

	sum_thread_stats(&client_ts, &p->ts, sum_stat_nr);
	sum_group_stats(&client_gs, &p->rs);

	client_ts.members++;
	client_ts.groupid = p->ts.groupid;

	if (++sum_stat_nr == sum_stat_clients) {
		strcpy(client_ts.name, "All clients");
		show_thread_status(&client_ts, &client_gs);
	}
}

static void handle_gs(struct fio_net_cmd *cmd)
{
	struct group_run_stats *gs = (struct group_run_stats *) cmd->payload;

	convert_gs(gs, gs);
	show_group_stats(gs);
}

static void convert_agg(struct disk_util_agg *agg)
{
	int i;

	for (i = 0; i < 2; i++) {
		agg->ios[i]	= le32_to_cpu(agg->ios[i]);
		agg->merges[i]	= le32_to_cpu(agg->merges[i]);
		agg->sectors[i]	= le64_to_cpu(agg->sectors[i]);
		agg->ticks[i]	= le32_to_cpu(agg->ticks[i]);
	}

	agg->io_ticks		= le32_to_cpu(agg->io_ticks);
	agg->time_in_queue	= le32_to_cpu(agg->time_in_queue);
	agg->slavecount		= le32_to_cpu(agg->slavecount);
	agg->max_util.u.f	= fio_uint64_to_double(__le64_to_cpu(agg->max_util.u.i));
}

static void convert_dus(struct disk_util_stat *dus)
{
	int i;

	for (i = 0; i < 2; i++) {
		dus->ios[i]	= le32_to_cpu(dus->ios[i]);
		dus->merges[i]	= le32_to_cpu(dus->merges[i]);
		dus->sectors[i]	= le64_to_cpu(dus->sectors[i]);
		dus->ticks[i]	= le32_to_cpu(dus->ticks[i]);
	}

	dus->io_ticks		= le32_to_cpu(dus->io_ticks);
	dus->time_in_queue	= le32_to_cpu(dus->time_in_queue);
	dus->msec		= le64_to_cpu(dus->msec);
}

static void handle_du(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_du_pdu *du = (struct cmd_du_pdu *) cmd->payload;

	convert_dus(&du->dus);
	convert_agg(&du->agg);

	if (!client->disk_stats_shown) {
		client->disk_stats_shown = 1;
		log_info("\nDisk stats (read/write):\n");
	}

	print_disk_util(&du->dus, &du->agg, output_format == FIO_OUTPUT_TERSE);
}

static void convert_jobs_eta(struct jobs_eta *je)
{
	int i;

	je->nr_running		= le32_to_cpu(je->nr_running);
	je->nr_ramp		= le32_to_cpu(je->nr_ramp);
	je->nr_pending		= le32_to_cpu(je->nr_pending);
	je->files_open		= le32_to_cpu(je->files_open);
	je->m_rate		= le32_to_cpu(je->m_rate);
	je->t_rate		= le32_to_cpu(je->t_rate);
	je->m_iops		= le32_to_cpu(je->m_iops);
	je->t_iops		= le32_to_cpu(je->t_iops);

	for (i = 0; i < 2; i++) {
		je->rate[i]	= le32_to_cpu(je->rate[i]);
		je->iops[i]	= le32_to_cpu(je->iops[i]);
	}

	je->elapsed_sec		= le64_to_cpu(je->elapsed_sec);
	je->eta_sec		= le64_to_cpu(je->eta_sec);
	je->is_pow2		= le32_to_cpu(je->is_pow2);
}

static void sum_jobs_eta(struct jobs_eta *dst, struct jobs_eta *je)
{
	int i;

	dst->nr_running		+= je->nr_running;
	dst->nr_ramp		+= je->nr_ramp;
	dst->nr_pending		+= je->nr_pending;
	dst->files_open		+= je->files_open;
	dst->m_rate		+= je->m_rate;
	dst->t_rate		+= je->t_rate;
	dst->m_iops		+= je->m_iops;
	dst->t_iops		+= je->t_iops;

	for (i = 0; i < 2; i++) {
		dst->rate[i]	+= je->rate[i];
		dst->iops[i]	+= je->iops[i];
	}

	dst->elapsed_sec	+= je->elapsed_sec;

	if (je->eta_sec > dst->eta_sec)
		dst->eta_sec = je->eta_sec;
}

static void dec_jobs_eta(struct client_eta *eta)
{
	if (!--eta->pending) {
		display_thread_status(&eta->eta);
		free(eta);
	}
}

static void remove_reply_cmd(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct fio_net_int_cmd *icmd = NULL;
	struct flist_head *entry;

	flist_for_each(entry, &client->cmd_list) {
		icmd = flist_entry(entry, struct fio_net_int_cmd, list);

		if (cmd->tag == (uintptr_t) icmd)
			break;

		icmd = NULL;
	}

	if (!icmd) {
		log_err("fio: client: unable to find matching tag\n");
		return;
	}

	flist_del(&icmd->list);
	cmd->tag = icmd->saved_tag;
	free(icmd);
}

static void handle_eta(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct jobs_eta *je = (struct jobs_eta *) cmd->payload;
	struct client_eta *eta = (struct client_eta *) (uintptr_t) cmd->tag;

	dprint(FD_NET, "client: got eta tag %p, %d\n", eta, eta->pending);

	assert(client->eta_in_flight == eta);

	client->eta_in_flight = NULL;
	flist_del_init(&client->eta_list);

	convert_jobs_eta(je);
	sum_jobs_eta(&eta->eta, je);
	dec_jobs_eta(eta);
}

static void handle_probe(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu *probe = (struct cmd_probe_pdu *) cmd->payload;
	const char *os, *arch;
	char bit[16];

	os = fio_get_os_string(probe->os);
	if (!os)
		os = "unknown";

	arch = fio_get_arch_string(probe->arch);
	if (!arch)
		os = "unknown";

	sprintf(bit, "%d-bit", probe->bpp * 8);

	log_info("hostname=%s, be=%u, %s, os=%s, arch=%s, fio=%s\n",
		probe->hostname, probe->bigendian, bit, os, arch,
		probe->fio_version);

	if (!client->name)
		client->name = strdup((char *) probe->hostname);
}

static void handle_start(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_start_pdu *pdu = (struct cmd_start_pdu *) cmd->payload;

	client->state = Client_started;
	client->jobs = le32_to_cpu(pdu->jobs);
	client->nr_stat = le32_to_cpu(pdu->stat_outputs);

	if (sum_stat_clients > 1)
		do_output_all_clients = 1;

	sum_stat_clients += client->nr_stat;
}

static void handle_stop(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_end_pdu *pdu = (struct cmd_end_pdu *) cmd->payload;

	client->state = Client_stopped;
	client->error = le32_to_cpu(pdu->error);

	if (client->error)
		log_info("client <%s>: exited with error %d\n", client->hostname, client->error);
}

static int handle_client(struct fio_client *client)
{
	struct fio_net_cmd *cmd;

	dprint(FD_NET, "client: handle %s\n", client->hostname);

	cmd = fio_net_recv_cmd(client->fd);
	if (!cmd)
		return 0;

	dprint(FD_NET, "client: got cmd op %s from %s\n",
				fio_server_op(cmd->opcode), client->hostname);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
		remove_client(client);
		free(cmd);
		break;
	case FIO_NET_CMD_TEXT: {
		const char *buf = (const char *) cmd->payload;
		const char *name;
		int fio_unused ret;

		name = client->name ? client->name : client->hostname;

		if (!client->skip_newline)
			fprintf(f_out, "<%s> ", name);
		ret = fwrite(buf, cmd->pdu_len, 1, f_out);
		fflush(f_out);
		client->skip_newline = strchr(buf, '\n') == NULL;
		free(cmd);
		break;
		}
	case FIO_NET_CMD_DU:
		handle_du(client, cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_TS:
		handle_ts(client, cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_GS:
		handle_gs(cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_ETA:
		remove_reply_cmd(client, cmd);
		handle_eta(client, cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_PROBE:
		remove_reply_cmd(client, cmd);
		handle_probe(client, cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_RUN:
		client->state = Client_running;
		free(cmd);
		break;
	case FIO_NET_CMD_START:
		handle_start(client, cmd);
		free(cmd);
		break;
	case FIO_NET_CMD_STOP:
		handle_stop(client, cmd);
		free(cmd);
		break;
	default:
		log_err("fio: unknown client op: %s\n", fio_server_op(cmd->opcode));
		free(cmd);
		break;
	}

	return 1;
}

static void request_client_etas(void)
{
	struct fio_client *client;
	struct flist_head *entry;
	struct client_eta *eta;
	int skipped = 0;

	dprint(FD_NET, "client: request eta (%d)\n", nr_clients);

	eta = malloc(sizeof(*eta));
	memset(&eta->eta, 0, sizeof(eta->eta));
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

	while (skipped--)
		dec_jobs_eta(eta);

	dprint(FD_NET, "client: requested eta tag %p\n", eta);
}

static int client_check_cmd_timeout(struct fio_client *client,
				    struct timeval *now)
{
	struct fio_net_int_cmd *cmd;
	struct flist_head *entry, *tmp;
	int ret = 0;

	flist_for_each_safe(entry, tmp, &client->cmd_list) {
		cmd = flist_entry(entry, struct fio_net_int_cmd, list);

		if (mtime_since(&cmd->tv, now) < FIO_NET_CLIENT_TIMEOUT)
			continue;

		log_err("fio: client %s, timeout on cmd %s\n", client->hostname,
						fio_server_op(cmd->cmd.opcode));
		flist_del(&cmd->list);
		free(cmd);
		ret = 1;
	}

	return flist_empty(&client->cmd_list) && ret;
}

static int fio_client_timed_out(void)
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

		log_err("fio: client %s timed out\n", client->hostname);
		remove_client(client);
		ret = 1;
	}

	return ret;
}

int fio_handle_clients(void)
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

			if (!client->sent_job &&
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

			fio_gettime(&tv, NULL);
			if (mtime_since(&eta_tv, &tv) >= 900) {
				request_client_etas();
				memcpy(&eta_tv, &tv, sizeof(tv));

				if (fio_client_timed_out())
					break;
			}

			ret = poll(pfds, nr_clients, 100);
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
				log_err("fio: unknown client fd %d\n", pfds[i].fd);
				continue;
			}
			if (!handle_client(client)) {
				log_info("client: host=%s disconnected\n",
						client->hostname);
				remove_client(client);
				retval = 1;
			} else if (client->error)
				retval = 1;
			put_client(client);
		}
	}

	free(pfds);
	return retval;
}
