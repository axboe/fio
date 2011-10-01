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

#include "fio.h"
#include "server.h"
#include "crc/crc16.h"

int fio_net_port = 8765;

int exit_backend = 0;

static char *job_buf;
static unsigned int job_cur_len;
static unsigned int job_max_len;

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

struct fio_net_cmd *fio_net_cmd_read(int sk)
{
	struct fio_net_cmd cmd, *ret = NULL;
	uint16_t crc;

	if (fio_recv_data(sk, &cmd, sizeof(cmd)))
		return NULL;

	/* We have a command, verify it and swap if need be */
	if (verify_convert_cmd(&cmd))
		return NULL;

	/* Command checks out, alloc real command and fill in */
	ret = malloc(sizeof(cmd) + cmd.pdu_len);
	memcpy(ret, &cmd, sizeof(cmd));

	if (!ret->pdu_len)
		return ret;

	/* There's payload, get it */
	if (fio_recv_data(sk, (void *) ret + sizeof(*ret), ret->pdu_len)) {
		free(ret);
		return NULL;
	}

	/* Verify payload crc */
	crc = crc16(ret->payload, ret->pdu_len);
	if (crc != ret->pdu_crc16) {
		log_err("fio: server bad crc on payload (got %x, wanted %x)\n",
				ret->pdu_crc16, crc);
		free(ret);
		return NULL;
	}

	return ret;
}

void fio_net_cmd_crc(struct fio_net_cmd *cmd)
{
	uint32_t pdu_len;

	cmd->cmd_crc16 = cpu_to_le16(crc16(cmd, FIO_NET_CMD_CRC_SZ));

	pdu_len = le32_to_cpu(cmd->pdu_len);
	if (pdu_len)
		cmd->pdu_crc16 = cpu_to_le16(crc16(cmd->payload, pdu_len));
}

int fio_net_send_cmd(int fd, uint16_t opcode, const char *buf, off_t size)
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
			cmd->flags |= FIO_NET_CMD_F_MORE;

		fio_net_cmd_crc(cmd);

		ret = fio_send_data(fd, cmd, sizeof(*cmd) + this_len);
		free(cmd);
		size -= this_len;
		buf += this_len;
	} while (!ret && size);

	return ret;
}

static int send_simple_command(int sk, uint16_t opcode, uint64_t serial)
{
	struct fio_net_cmd cmd = {
		.version	= cpu_to_le16(FIO_SERVER_VER1),
		.opcode		= cpu_to_le16(opcode),
		.serial		= cpu_to_le64(serial),
	};

	fio_net_cmd_crc(&cmd);

	return fio_send_data(sk, &cmd, sizeof(cmd));
}

/*
 * Send an ack for this command
 */
static int ack_command(int sk, struct fio_net_cmd *cmd)
{
#if 0
	return send_simple_command(sk, FIO_NET_CMD_ACK, cmd->serial);
#else
	return 0;
#endif
}

#if 0
static int nak_command(int sk, struct fio_net_cmd *cmd)
{
	return send_simple_command(sk, FIO_NET_CMD_NAK, cmd->serial);
}
#endif

static int send_quit_command(void)
{
	dprint(FD_NET, "server: sending quit\n");
	return send_simple_command(server_fd, FIO_NET_CMD_QUIT, 0);
}

static int handle_cur_job(struct fio_net_cmd *cmd)
{
	unsigned int left = job_max_len - job_cur_len;
	int ret = 0;

	if (left < cmd->pdu_len) {
		job_buf = realloc(job_buf, job_max_len + 2 * cmd->pdu_len);
		job_max_len += 2 * cmd->pdu_len;
	}

	memcpy(job_buf + job_cur_len, cmd->payload, cmd->pdu_len);
	job_cur_len += cmd->pdu_len;

	/*
	 * More data coming for this job
	 */
	if (cmd->flags & FIO_NET_CMD_F_MORE)
		return 0;

	parse_jobs_ini(job_buf, 1, 0);
	ret = exec_run();
	send_quit_command();
	reset_fio_state();
	free(job_buf);
	job_buf = NULL;
	job_cur_len = job_max_len = 0;
	return ret;
}

static int handle_command(struct fio_net_cmd *cmd)
{
	int ret;

	dprint(FD_NET, "server: got opcode %d\n", cmd->opcode);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
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
		cmd = fio_net_cmd_read(sk);
		if (!cmd) {
			ret = 1;
			break;
		}

		ret = ack_command(sk, cmd);
		if (ret)
			break;

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

	exitval = handle_connection(sk);

	server_fd = -1;
	close(sk);

	if (!exit_backend)
		goto again;

out:
	return exitval;
}

int fio_server(void)
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
