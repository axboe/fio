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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>

#include "fio.h"
#include "server.h"
#include "crc/crc32.h"
#include "flist.h"

struct fio_client {
	struct flist_head list;
	struct sockaddr_in addr;
	char *hostname;
	int fd;

	int state;
	int skip_newline;

	uint16_t argc;
	char **argv;
};

enum {
	Client_created		= 0,
	Client_connected	= 1,
	Client_started		= 2,
	Client_stopped		= 3,
	Client_exited		= 4,
};

static FLIST_HEAD(client_list);

static int handle_client(struct fio_client *client, int one);

static struct fio_client *find_client_by_fd(int fd)
{
	struct fio_client *client;
	struct flist_head *entry;

	flist_for_each(entry, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (client->fd == fd)
			return client;
	}

	return NULL;
}

static struct fio_client *find_client_by_name(const char *name)
{
	struct fio_client *client;
	struct flist_head *entry;

	flist_for_each(entry, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (!strcmp(name, client->hostname))
			return client;
	}

	return NULL;
}

static void remove_client(struct fio_client *client)
{
	dprint(FD_NET, "client: removed <%s>\n", client->hostname);
	flist_del(&client->list);
	nr_clients--;

	free(client->hostname);
	if (client->argv)
		free(client->argv);

	free(client);
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

void fio_client_add_cmd_option(const char *hostname, const char *opt)
{
	struct fio_client *client;

	if (!hostname || !opt)
		return;

	client = find_client_by_name(hostname);
	if (!client) {
		log_err("fio: unknown client %s\n", hostname);
		return;
	}

	__fio_client_add_cmd_option(client, opt);
}

void fio_client_add(const char *hostname)
{
	struct fio_client *client;

	dprint(FD_NET, "client: added  <%s>\n", hostname);
	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));

	client->hostname = strdup(hostname);
	client->fd = -1;

	__fio_client_add_cmd_option(client, "fio");

	flist_add(&client->list, &client_list);
	nr_clients++;
}

static int fio_client_connect(struct fio_client *client)
{
	int fd;

	dprint(FD_NET, "client: connect to host %s\n", client->hostname);

	memset(&client->addr, 0, sizeof(client->addr));
	client->addr.sin_family = AF_INET;
	client->addr.sin_port = htons(fio_net_port);

	if (inet_aton(client->hostname, &client->addr.sin_addr) != 1) {
		struct hostent *hent;

		hent = gethostbyname(client->hostname);
		if (!hent) {
			log_err("fio: gethostbyname: %s\n", strerror(errno));
			return 1;
		}

		memcpy(&client->addr.sin_addr, hent->h_addr, 4);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return 1;
	}

	if (connect(fd, (struct sockaddr *) &client->addr, sizeof(client->addr)) < 0) {
		log_err("fio: connect: %s\n", strerror(errno));
		log_err("fio: failed to connect to %s\n", client->hostname);
		return 1;
	}

	client->fd = fd;
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

		fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_QUIT, 0);
	}
}

static void sig_int(int sig)
{
	dprint(FD_NET, "client: got sign %d\n", sig);
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
}

static void probe_client(struct fio_client *client)
{
	dprint(FD_NET, "client: send probe\n");

	fio_net_send_simple_cmd(client->fd, FIO_NET_CMD_PROBE, 0);
	handle_client(client, 1);
}

static int send_client_cmd_line(struct fio_client *client)
{
	struct cmd_line_pdu *pdu;
	int i, ret;

	dprint(FD_NET, "client: send cmdline %d\n", client->argc);

	pdu = malloc(sizeof(*pdu));
	for (i = 0; i < client->argc; i++)
		strcpy((char *) pdu->argv[i], client->argv[i]);

	pdu->argc = cpu_to_le16(client->argc);
	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOBLINE, pdu, sizeof(*pdu));
	free(pdu);
	return ret;
}

int fio_clients_connect(void)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;
	int ret;

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
		log_err("fio: job file open: %s\n", strerror(errno));
		return 1;
	}

	if (fstat(fd, &sb) < 0) {
		log_err("fio: job file stat: %s\n", strerror(errno));
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
		return 1;
	}

	ret = fio_net_send_cmd(client->fd, FIO_NET_CMD_JOB, buf, sb.st_size);
	free(buf);
	return ret;
}

int fio_clients_send_ini(const char *filename)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		if (fio_client_send_ini(client, filename))
			remove_client(client);
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

static void handle_ts(struct fio_net_cmd *cmd)
{
	struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;

	convert_ts(&p->ts, &p->ts);
	convert_gs(&p->rs, &p->rs);

	show_thread_status(&p->ts, &p->rs);
}

static void handle_gs(struct fio_net_cmd *cmd)
{
	struct group_run_stats *gs = (struct group_run_stats *) cmd->payload;

	convert_gs(gs, gs);
	show_group_stats(gs);
}

static void handle_eta(struct fio_net_cmd *cmd)
{
	struct jobs_eta *je = (struct jobs_eta *) cmd->payload;
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

	je->elapsed_sec		= le32_to_cpu(je->nr_running);
	je->eta_sec		= le64_to_cpu(je->eta_sec);

	display_thread_status(je);
}

static void handle_probe(struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu *probe = (struct cmd_probe_pdu *) cmd->payload;

	log_info("Probe: hostname=%s, be=%u, fio ver %u.%u.%u\n",
		probe->hostname, probe->bigendian, probe->fio_major,
		probe->fio_minor, probe->fio_patch);
}

static int handle_client(struct fio_client *client, int one)
{
	struct fio_net_cmd *cmd;
	int done = 0;

	dprint(FD_NET, "client: handle %s\n", client->hostname);

	while ((cmd = fio_net_recv_cmd(client->fd, 1)) != NULL) {
		dprint(FD_NET, "%s: got cmd op %d\n", client->hostname,
							cmd->opcode);

		switch (cmd->opcode) {
		case FIO_NET_CMD_QUIT:
			remove_client(client);
			free(cmd);
			done = 1;
			break;
		case FIO_NET_CMD_TEXT: {
			const char *buf = (const char *) cmd->payload;
			int fio_unused ret;

			if (!client->skip_newline)
				fprintf(f_out, "Client <%s>: ", client->hostname);
			ret = fwrite(buf, cmd->pdu_len, 1, f_out);
			fflush(f_out);
			client->skip_newline = strchr(buf, '\n') == NULL;
			free(cmd);
			break;
			}
		case FIO_NET_CMD_TS:
			handle_ts(cmd);
			free(cmd);
			break;
		case FIO_NET_CMD_GS:
			handle_gs(cmd);
			free(cmd);
			break;
		case FIO_NET_CMD_ETA:
			handle_eta(cmd);
			free(cmd);
			break;
		case FIO_NET_CMD_PROBE:
			handle_probe(cmd);
			free(cmd);
			break;
		case FIO_NET_CMD_START:
			client->state = Client_started;
			free(cmd);
			break;
		case FIO_NET_CMD_STOP:
			client->state = Client_stopped;
			free(cmd);
			break;
		default:
			log_err("fio: unknown client op: %d\n", cmd->opcode);
			free(cmd);
			break;
		}

		if (done || one)
			break;
	}

	return 0;
}

int fio_handle_clients(void)
{
	struct fio_client *client;
	struct flist_head *entry;
	struct pollfd *pfds;
	int i, ret = 0;

	pfds = malloc(nr_clients * sizeof(struct pollfd));

	while (!exit_backend && nr_clients) {
		i = 0;
		flist_for_each(entry, &client_list) {
			client = flist_entry(entry, struct fio_client, list);

			pfds[i].fd = client->fd;
			pfds[i].events = POLLIN;
			i++;
		}

		assert(i == nr_clients);

		do {
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
				log_err("fio: unknown client\n");
				continue;
			}
			handle_client(client, 0);
		}
	}

	free(pfds);
	return 0;
}
