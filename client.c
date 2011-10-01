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
#include "flist.h"

struct fio_client {
	struct flist_head list;
	struct sockaddr_in addr;
	char *hostname;
	int fd;
};

static FLIST_HEAD(client_list);

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

#if 0
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
#endif

static void remove_client(struct fio_client *client)
{
	flist_del(&client->list);
	nr_clients--;
	free(client->hostname);
	free(client);
}

void fio_client_add(const char *hostname)
{
	struct fio_client *client;

	client = malloc(sizeof(*client));
	memset(client, 0, sizeof(*client));
	client->hostname = strdup(hostname);
	client->fd = -1;
	flist_add(&client->list, &client_list);
	nr_clients++;
}

static int fio_client_connect(struct fio_client *client)
{
	int fd;

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
		free(client);
		return 1;
	}

	if (connect(fd, (struct sockaddr *) &client->addr, sizeof(client->addr)) < 0) {
		log_err("fio: connect: %s\n", strerror(errno));
		free(client);
		return 1;
	}

	client->fd = fd;
	return 0;
}

int fio_clients_connect(void)
{
	struct fio_client *client;
	struct flist_head *entry, *tmp;
	int ret;

	flist_for_each_safe(entry, tmp, &client_list) {
		client = flist_entry(entry, struct fio_client, list);

		ret = fio_client_connect(client);
		if (ret)
			remove_client(client);
	}

	return !nr_clients;
}

static int send_file_buf(struct fio_client *client, char *buf, off_t size)
{
	return fio_net_send_cmd(client->fd, FIO_NET_CMD_JOB, buf, size);
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

	ret = send_file_buf(client, buf, sb.st_size);
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

static int handle_client(struct fio_client *client)
{
	struct fio_net_cmd *cmd;

	while ((cmd = fio_net_cmd_read(client->fd)) != NULL) {
		if (cmd->opcode == FIO_NET_CMD_ACK) {
			free(cmd);
			continue;
		}
		if (cmd->opcode == FIO_NET_CMD_QUIT) {
			remove_client(client);
			free(cmd);
			break;
		}
		if (cmd->opcode != FIO_NET_CMD_TEXT) {
			printf("non text: %d\n", cmd->opcode);
			free(cmd);
			continue;
		}
		fwrite(cmd->payload, cmd->pdu_len, 1, stdout);
		fflush(stdout);
		free(cmd);
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

		ret = poll(pfds, nr_clients, 100);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			log_err("fio: poll clients: %s\n", strerror(errno));
			break;
		} else if (!ret)
			continue;

		for (i = 0; i < nr_clients; i++) {
			if (!(pfds[i].revents & POLLIN))
				continue;

			client = find_client_by_fd(pfds[i].fd);
			if (!client) {
				log_err("fio: unknown client\n");
				continue;
			}
			handle_client(client);
		}
	}

	free(pfds);

	return 0;
}
