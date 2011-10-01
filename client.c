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
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "fio.h"
#include "server.h"
#include "crc/crc32.h"

int fio_client_fd = -1;

int fio_client_connect(const char *host)
{
	struct sockaddr_in addr;
	int fd;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(fio_net_port);

	if (inet_aton(host, &addr.sin_addr) != 1) {
		struct hostent *hent;

		hent = gethostbyname(host);
		if (!hent) {
			log_err("fio: gethostbyname: %s\n", strerror(errno));
			return 1;
		}

		memcpy(&addr.sin_addr, hent->h_addr, 4);
	}

	fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return 1;
	}

	if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		log_err("fio: connect: %s\n", strerror(errno));
		return 1;
	}

	fio_client_fd = fd;
	return 0;
}

static int send_file_buf(char *buf, off_t size)
{
	struct fio_net_cmd *cmd;
	int ret;

	cmd = malloc(sizeof(*cmd) + size);

	fio_init_net_cmd(cmd, FIO_NET_CMD_JOB_END, buf, size);
	fio_net_cmd_crc(cmd);

	ret = fio_send_data(fio_client_fd, cmd, sizeof(*cmd) + size);
	free(cmd);
	return ret;
}

/*
 * Send file contents to server backend. We could use sendfile(), but to remain
 * more portable lets just read/write the darn thing.
 */
int fio_client_send_ini(const char *filename)
{
	struct stat sb;
	char *p, *buf;
	off_t len;
	int fd, ret;

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

	ret = send_file_buf(buf, sb.st_size);
	free(buf);
	return ret;
}

int fio_handle_clients(void)
{
	struct fio_net_cmd *cmd;

	while (!exit_backend) {
		cmd = fio_net_cmd_read(fio_client_fd);
		if (!cmd)
			continue;

		if (cmd->opcode == FIO_NET_CMD_ACK) {
			free(cmd);
			continue;
		}
		if (cmd->opcode != FIO_NET_CMD_TEXT) {
			printf("non text: %d\n", cmd->opcode);
			free(cmd);
			continue;
		}
		printf("%s", cmd->payload);
		fflush(stdout);
		free(cmd);
	}

	return 0;
}
