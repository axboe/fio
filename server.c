#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>

#include "fio.h"
#include "server.h"
#include "crc/crc16.h"

int fio_net_port = 8765;

int exit_backend = 0;

static int server_fd = -1;

int fio_send_data(int sk, const void *p, unsigned int len)
{
	assert(len <= sizeof(struct fio_net_cmd) + FIO_SERVER_MAX_PDU);

	do {
		int ret = send(sk, p, len, 0);

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
	} while (!exit_backend);

	if (!len)
		return 0;

	return 1;
}

int fio_recv_data(int sk, void *p, unsigned int len)
{
	do {
		int ret = recv(sk, p, len, MSG_WAITALL);

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
	} while (!exit_backend);

	if (!len)
		return 0;

	return -1;
}

static int verify_convert_cmd(struct fio_net_cmd *cmd)
{
	uint16_t crc;

	cmd->cmd_crc16 = le16_to_cpu(cmd->cmd_crc16);
	cmd->pdu_crc16 = le16_to_cpu(cmd->pdu_crc16);

	crc = crc16(cmd, FIO_NET_CMD_CRC_SZ);
	if (crc != cmd->cmd_crc16) {
		log_err("fio: server bad crc on command (got %x, wanted %x)\n",
				cmd->cmd_crc16, crc);
		return 1;
	}

	cmd->version	= le16_to_cpu(cmd->version);
	cmd->opcode	= le16_to_cpu(cmd->opcode);
	cmd->flags	= le32_to_cpu(cmd->flags);
	cmd->serial	= le64_to_cpu(cmd->serial);
	cmd->pdu_len	= le32_to_cpu(cmd->pdu_len);

	switch (cmd->version) {
	case FIO_SERVER_VER1:
		break;
	default:
		log_err("fio: bad server cmd version %d\n", cmd->version);
		return 1;
	}

	if (cmd->pdu_len > FIO_SERVER_MAX_PDU) {
		log_err("fio: command payload too large: %u\n", cmd->pdu_len);
		return 1;
	}

	return 0;
}

/*
 * Read (and defragment, if necessary) incoming commands
 */
struct fio_net_cmd *fio_net_recv_cmd(int sk)
{
	struct fio_net_cmd cmd, *cmdret = NULL;
	size_t cmd_size = 0, pdu_offset = 0;
	uint16_t crc;
	int ret, first = 1;
	void *pdu = NULL;

	do {
		struct pollfd pfd;

		pfd.fd = sk;
		pfd.events = POLLIN;
		ret = 0;
		do {
			ret = poll(&pfd, 1, 100);
			if (ret < 0) {
				log_err("fio: poll: %s\n", strerror(errno));
				break;
			} else if (!ret)
				continue;

			if (pfd.revents & POLLIN)
				break;
			if (pfd.revents & (POLLERR|POLLHUP)) {
				ret = 1;
				break;
			}
		} while (ret >= 0);

		if (ret < 0)
			break;

		ret = fio_recv_data(sk, &cmd, sizeof(cmd));
		if (ret)
			break;

		/* We have a command, verify it and swap if need be */
		ret = verify_convert_cmd(&cmd);
		if (ret)
			break;

		if (first)
			cmd_size = sizeof(cmd) + cmd.pdu_len;
		else
			cmd_size += cmd.pdu_len;

		cmdret = realloc(cmdret, cmd_size);

		if (first)
			memcpy(cmdret, &cmd, sizeof(cmd));
		else
			assert(cmdret->opcode == cmd.opcode);

		if (!cmd.pdu_len)
			break;

		/* There's payload, get it */
		pdu = (void *) cmdret->payload + pdu_offset;
		ret = fio_recv_data(sk, pdu, cmd.pdu_len);
		if (ret)
			break;

		/* Verify payload crc */
		crc = crc16(pdu, cmd.pdu_len);
		if (crc != cmd.pdu_crc16) {
			log_err("fio: server bad crc on payload ");
			log_err("(got %x, wanted %x)\n", cmd.pdu_crc16, crc);
			ret = 1;
			break;
		}

		pdu_offset += cmd.pdu_len;
		if (!first)
			cmdret->pdu_len += cmd.pdu_len;
		first = 0;
	} while (cmd.flags & FIO_NET_CMD_F_MORE);

	if (ret) {
		free(cmdret);
		cmdret = NULL;
	} else if (cmdret)
		cmdret->flags &= ~FIO_NET_CMD_F_MORE;

	return cmdret;
}

void fio_net_cmd_crc(struct fio_net_cmd *cmd)
{
	uint32_t pdu_len;

	cmd->cmd_crc16 = __cpu_to_le16(crc16(cmd, FIO_NET_CMD_CRC_SZ));

	pdu_len = le32_to_cpu(cmd->pdu_len);
	if (pdu_len)
		cmd->pdu_crc16 = __cpu_to_le16(crc16(cmd->payload, pdu_len));
}

int fio_net_send_cmd(int fd, uint16_t opcode, const void *buf, off_t size)
{
	struct fio_net_cmd *cmd;
	size_t this_len;
	int ret;

	do {
		this_len = size;
		if (this_len > FIO_SERVER_MAX_PDU)
			this_len = FIO_SERVER_MAX_PDU;

		cmd = malloc(sizeof(*cmd) + this_len);

		fio_init_net_cmd(cmd, opcode, buf, this_len);

		if (this_len < size)
			cmd->flags = __cpu_to_le32(FIO_NET_CMD_F_MORE);

		fio_net_cmd_crc(cmd);

		ret = fio_send_data(fd, cmd, sizeof(*cmd) + this_len);
		free(cmd);
		size -= this_len;
		buf += this_len;
	} while (!ret && size);

	return ret;
}

int fio_net_send_simple_cmd(int sk, uint16_t opcode, uint64_t serial)
{
	struct fio_net_cmd cmd = {
		.version	= __cpu_to_le16(FIO_SERVER_VER1),
		.opcode		= cpu_to_le16(opcode),
		.serial		= cpu_to_le64(serial),
	};

	fio_net_cmd_crc(&cmd);

	return fio_send_data(sk, &cmd, sizeof(cmd));
}

static int send_quit_command(void)
{
	dprint(FD_NET, "server: sending quit\n");
	return fio_net_send_simple_cmd(server_fd, FIO_NET_CMD_QUIT, 0);
}

static int handle_cur_job(struct fio_net_cmd *cmd)
{
	void *buf = cmd->payload;
	int ret;

	parse_jobs_ini(buf, 1, 0);
	ret = exec_run();
	send_quit_command();
	reset_fio_state();
	return ret;
}

static int handle_command(struct fio_net_cmd *cmd)
{
	int ret;

	dprint(FD_NET, "server: got opcode %d\n", cmd->opcode);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
		fio_terminate_threads(TERMINATE_ALL);
		return 1;
	case FIO_NET_CMD_EXIT:
		exit_backend = 1;
		return 1;
	case FIO_NET_CMD_ACK:
		return 0;
	case FIO_NET_CMD_NAK:
		return 1;
	case FIO_NET_CMD_JOB:
		ret = handle_cur_job(cmd);
		break;
	default:
		log_err("fio: unknown opcode: %d\n", cmd->opcode);
		ret = 1;
	}

	return ret;
}

static int handle_connection(int sk)
{
	struct fio_net_cmd *cmd = NULL;
	int ret = 0;

	/* read forever */
	while (!exit_backend) {
		cmd = fio_net_recv_cmd(sk);
		if (!cmd) {
			ret = 1;
			break;
		}

		ret = handle_command(cmd);
		if (ret)
			break;

		free(cmd);
		cmd = NULL;
	}

	if (cmd)
		free(cmd);

	return ret;
}

void fio_server_idle_loop(void)
{
	if (server_fd != -1)
		handle_connection(server_fd);
}

static int accept_loop(int listen_sk)
{
	struct sockaddr addr;
	unsigned int len = sizeof(addr);
	struct pollfd pfd;
	int ret, sk, flags, exitval = 0;

	flags = fcntl(listen_sk, F_GETFL);
	flags |= O_NONBLOCK;
	fcntl(listen_sk, F_SETFL, flags);
again:
	pfd.fd = listen_sk;
	pfd.events = POLLIN;
	do {
		ret = poll(&pfd, 1, 100);
		if (ret < 0) {
			if (errno == EINTR)
				break;
			log_err("fio: poll: %s\n", strerror(errno));
			goto out;
		} else if (!ret)
			continue;

		if (pfd.revents & POLLIN)
			break;
	} while (!exit_backend);

	if (exit_backend)
		goto out;

	sk = accept(listen_sk, &addr, &len);
	if (sk < 0) {
		log_err("fio: accept: %s\n", strerror(errno));
		return -1;
	}

	dprint(FD_NET, "server got a connection\n");

	server_fd = sk;

	printf("handle\n");

	exitval = handle_connection(sk);

	printf("out, exit %d\n", exitval);

	server_fd = -1;
	close(sk);

	if (!exit_backend)
		goto again;

out:
	return exitval;
}

static int fio_server(void)
{
	struct sockaddr_in saddr_in;
	struct sockaddr addr;
	unsigned int len;
	int sk, opt, ret;

	dprint(FD_NET, "starting server\n");

	sk = socket(AF_INET, SOCK_STREAM, 0);
	if (sk < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	opt = 1;
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_err("fio: setsockopt: %s\n", strerror(errno));
		return -1;
	}
#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
		log_err("fio: setsockopt: %s\n", strerror(errno));
		return 1;
	}
#endif

	saddr_in.sin_family = AF_INET;
	saddr_in.sin_addr.s_addr = htonl(INADDR_ANY);
	saddr_in.sin_port = htons(fio_net_port);

	if (bind(sk, (struct sockaddr *) &saddr_in, sizeof(saddr_in)) < 0) {
		log_err("fio: bind: %s\n", strerror(errno));
		return -1;
	}

	if (listen(sk, 1) < 0) {
		log_err("fio: listen: %s\n", strerror(errno));
		return -1;
	}

	len = sizeof(addr);
	if (getsockname(sk, &addr, &len) < 0) {
		log_err("fio: getsockname: %s\n", strerror(errno));
		return -1;
	}

	ret = accept_loop(sk);
	close(sk);
	return ret;
}

int fio_server_text_output(const char *buf, unsigned int len)
{
	if (server_fd != -1)
		return fio_net_send_cmd(server_fd, FIO_NET_CMD_TEXT, buf, len);

	return 0;
}

static void convert_io_stat(struct io_stat *dst, struct io_stat *src)
{
	dst->max_val	= cpu_to_le64(src->max_val);
	dst->min_val	= cpu_to_le64(src->min_val);
	dst->samples	= cpu_to_le64(src->samples);
	/* FIXME */
	dst->mean	= __cpu_to_le64(src->mean);
	dst->S		= __cpu_to_le64(src->S);
}

static void convert_gs(struct group_run_stats *dst, struct group_run_stats *src)
{
	int i;

	for (i = 0; i < 2; i++) {
		dst->max_run[i]		= cpu_to_le64(src->max_run[i]);
		dst->min_run[i]		= cpu_to_le64(src->min_run[i]);
		dst->max_bw[i]		= cpu_to_le64(src->max_bw[i]);
		dst->min_bw[i]		= cpu_to_le64(src->min_bw[i]);
		dst->io_kb[i]		= cpu_to_le64(src->io_kb[i]);
		dst->agg[i]		= cpu_to_le64(src->agg[i]);
	}

	dst->kb_base	= cpu_to_le32(src->kb_base);
	dst->groupid	= cpu_to_le32(src->groupid);
}

/*
 * Send a CMD_TS, which packs struct thread_stat and group_run_stats
 * into a single payload.
 */
void fio_server_send_ts(struct thread_stat *ts, struct group_run_stats *rs)
{
	struct cmd_ts_pdu p;
	int i, j;

	strcpy(p.ts.name, ts->name);
	strcpy(p.ts.verror, ts->verror);
	strcpy(p.ts.description, ts->description);

	p.ts.error	= cpu_to_le32(ts->error);
	p.ts.groupid	= cpu_to_le32(ts->groupid);
	p.ts.pid	= cpu_to_le32(ts->pid);
	p.ts.members	= cpu_to_le32(ts->members);

	for (i = 0; i < 2; i++) {
		convert_io_stat(&p.ts.clat_stat[i], &ts->clat_stat[i]);
		convert_io_stat(&p.ts.slat_stat[i], &ts->slat_stat[i]);
		convert_io_stat(&p.ts.lat_stat[i], &ts->lat_stat[i]);
		convert_io_stat(&p.ts.bw_stat[i], &ts->bw_stat[i]);
	}

	p.ts.usr_time		= cpu_to_le64(ts->usr_time);
	p.ts.sys_time		= cpu_to_le64(ts->sys_time);
	p.ts.ctx		= cpu_to_le64(ts->ctx);
	p.ts.minf		= cpu_to_le64(ts->minf);
	p.ts.majf		= cpu_to_le64(ts->majf);
	p.ts.clat_percentiles	= cpu_to_le64(ts->clat_percentiles);
	p.ts.percentile_list	= NULL;

	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		p.ts.io_u_map[i]	= cpu_to_le32(ts->io_u_map[i]);
		p.ts.io_u_submit[i]	= cpu_to_le32(ts->io_u_submit[i]);
		p.ts.io_u_complete[i]	= cpu_to_le32(ts->io_u_complete[i]);
	}

	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++) {
		p.ts.io_u_lat_u[i]	= cpu_to_le32(ts->io_u_lat_u[i]);
		p.ts.io_u_lat_m[i]	= cpu_to_le32(ts->io_u_lat_m[i]);
	}

	for (i = 0; i < 2; i++)
		for (j = 0; j < FIO_IO_U_PLAT_NR; j++)
			p.ts.io_u_plat[i][j] = cpu_to_le32(ts->io_u_plat[i][j]);

	for (i = 0; i < 3; i++) {
		p.ts.total_io_u[i]	= cpu_to_le64(ts->total_io_u[i]);
		p.ts.short_io_u[i]	= cpu_to_le64(ts->total_io_u[i]);
	}

	p.ts.total_submit		= cpu_to_le64(ts->total_submit);
	p.ts.total_complete	= cpu_to_le64(ts->total_complete);

	for (i = 0; i < 2; i++) {
		p.ts.io_bytes[i]	= cpu_to_le64(ts->io_bytes[i]);
		p.ts.runtime[i]		= cpu_to_le64(ts->runtime[i]);
	}

	p.ts.total_run_time	= cpu_to_le64(ts->total_run_time);
	p.ts.continue_on_error	= cpu_to_le16(ts->continue_on_error);
	p.ts.total_err_count	= cpu_to_le64(ts->total_err_count);
	p.ts.first_error	= cpu_to_le32(ts->first_error);
	p.ts.kb_base		= cpu_to_le32(ts->kb_base);

	convert_gs(&p.rs, rs);

	fio_net_send_cmd(server_fd, FIO_NET_CMD_TS, &p, sizeof(p));
}

void fio_server_send_gs(struct group_run_stats *rs)
{
	struct group_run_stats gs;

	convert_gs(&gs, rs);
	fio_net_send_cmd(server_fd, FIO_NET_CMD_GS, &gs, sizeof(gs));
}

void fio_server_send_status(void)
{
	struct jobs_eta *je;
	size_t size;
	void *buf;
	int i;

	size = sizeof(*je) + thread_number * sizeof(char);
	buf = malloc(size);
	memset(buf, 0, size);
	je = buf;

	if (!calc_thread_status(je)) {
		free(je);
		return;
	}

	je->nr_running		= cpu_to_le32(je->nr_running);
	je->nr_ramp		= cpu_to_le32(je->nr_ramp);
	je->nr_pending		= cpu_to_le32(je->nr_pending);
	je->files_open		= cpu_to_le32(je->files_open);
	je->m_rate		= cpu_to_le32(je->m_rate);
	je->t_rate		= cpu_to_le32(je->t_rate);
	je->m_iops		= cpu_to_le32(je->m_iops);
	je->t_iops		= cpu_to_le32(je->t_iops);

	for (i = 0; i < 2; i++) {
		je->rate[i]	= cpu_to_le32(je->rate[i]);
		je->iops[i]	= cpu_to_le32(je->iops[i]);
	}

	je->elapsed_sec		= cpu_to_le32(je->nr_running);
	je->eta_sec		= cpu_to_le64(je->eta_sec);

	fio_net_send_cmd(server_fd, FIO_NET_CMD_ETA, buf, size);
	free(je);
}

int fio_server_log(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	return fio_server_text_output(buffer, len);
}

int fio_start_server(int daemonize)
{
	pid_t pid;

	if (!daemonize)
		return fio_server();

	openlog("fio", LOG_NDELAY|LOG_NOWAIT|LOG_PID, LOG_USER);
	pid = fork();
	if (pid < 0) {
		syslog(LOG_ERR, "failed server fork");
		return 1;
	} else if (pid)
		exit(0);

	setsid();
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	f_out = NULL;
	f_err = NULL;
	log_syslog = 1;
	return fio_server();
}
