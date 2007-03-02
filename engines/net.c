/*
 * Transfer data over the net.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>

#include "../fio.h"
#include "../os.h"

#define send_to_net(td)	((td)->io_ops->priv)

static int fio_netio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;

	/*
	 * Make sure we don't see spurious reads to a receiver, and vice versa
	 */
	if ((send_to_net(td) && io_u->ddir == DDIR_READ) ||
	    (!send_to_net(td) && io_u->ddir == DDIR_WRITE)) {
		td_verror(td, EINVAL, "bad direction");
		return 1;
	}
		
	if (io_u->ddir == DDIR_SYNC)
		return 0;
	if (io_u->offset == f->last_completed_pos)
		return 0;

	/*
	 * If offset is different from last end position, it's a seek.
	 * As network io is purely sequential, we don't allow seeks.
	 */
	td_verror(td, EINVAL, "cannot seek");
	return 1;
}

static int fio_netio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct fio_file *f = io_u->file;
	int ret, flags = 0;

	if (io_u->ddir == DDIR_WRITE) {
		/*
		 * if we are going to write more, set MSG_MORE
		 */
		if (td->this_io_bytes[DDIR_WRITE] + io_u->xfer_buflen <
		    td->io_size)
			flags = MSG_MORE;

		ret = send(f->fd, io_u->xfer_buf, io_u->xfer_buflen, flags);
	} else if (io_u->ddir == DDIR_READ) {
		flags = MSG_WAITALL;
		ret = recv(f->fd, io_u->xfer_buf, io_u->xfer_buflen, flags);
	} else
		ret = 0;	/* must be a SYNC */

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else
			io_u->error = errno;
	}

	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

static int fio_netio_setup_connect(struct thread_data *td, const char *host,
				   unsigned short port)
{
	struct sockaddr_in addr;
	struct fio_file *f;
	int i;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_aton(host, &addr.sin_addr) != 1) {
		struct hostent *hent;

		hent = gethostbyname(host);
		if (!hent) {
			td_verror(td, errno, "gethostbyname");
			return 1;
		}

		memcpy(&addr.sin_addr, hent->h_addr, 4);
	}

	for_each_file(td, f, i) {
		f->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (f->fd < 0) {
			td_verror(td, errno, "socket");
			return 1;
		}

		if (connect(f->fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
			td_verror(td, errno, "connect");
			return 1;
		}
	}

	return 0;

}

static int fio_netio_accept_connections(struct thread_data *td, int fd,
					struct sockaddr_in *addr)
{
	socklen_t socklen = sizeof(*addr);
	unsigned int accepts = 0;
	struct pollfd pfd;

	fprintf(f_out, "fio: waiting for %u connections\n", td->nr_files);

	/*
	 * Accept loop. poll for incoming events, accept them. Repeat until we
	 * have all connections.
	 */
	while (!td->terminate && accepts < td->nr_files) {
		struct fio_file *f;
		int ret, i;

		pfd.fd = fd;
		pfd.events = POLLIN;

		ret = poll(&pfd, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			td_verror(td, errno, "poll");
			break;
		} else if (!ret)
			continue;

		/*
		 * should be impossible
		 */
		if (!(pfd.revents & POLLIN))
			continue;

		for_each_file(td, f, i) {
			if (f->fd != -1)
				continue;

			f->fd = accept(fd, (struct sockaddr *) addr, &socklen);
			if (f->fd < 0) {
				td_verror(td, errno, "accept");
				return 1;
			}
			accepts++;
			break;
		}
	}

	td->nr_open_files = accepts;
	return 0;
}

static int fio_netio_setup_listen(struct thread_data *td, unsigned short port)
{
	struct sockaddr_in addr;
	int fd, opt;

	fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		td_verror(td, errno, "socket");
		return 1;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		td_verror(td, errno, "setsockopt");
		return 1;
	}
#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
		td_verror(td, errno, "setsockopt");
		return 1;
	}
#endif

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		td_verror(td, errno, "bind");
		return 1;
	}
	if (listen(fd, 1) < 0) {
		td_verror(td, errno, "listen");
		return 1;
	}

	return fio_netio_accept_connections(td, fd, &addr);
}

static int fio_netio_setup(struct thread_data *td)
{
	char host[64], buf[128];
	unsigned short port;
	struct fio_file *f;
	char *sep;
	int ret, i;

	if (!td->total_file_size) {
		log_err("fio: need size= set\n");
		return 1;
	}

	if (td_rw(td)) {
		log_err("fio: network connections must be read OR write\n");
		return 1;
	}

	strcpy(buf, td->filename);

	sep = strchr(buf, ':');
	if (!sep) {
		log_err("fio: bad network host:port <<%s>>\n", td->filename);
		return 1;
	}

	*sep = '\0';
	sep++;
	strcpy(host, buf);
	port = atoi(sep);

	if (td_read(td)) {
		send_to_net(td) = 0;
		ret = fio_netio_setup_listen(td, port);
	} else {
		send_to_net(td) = 1;
		ret = fio_netio_setup_connect(td, host, port);
	}

	if (ret)
		return ret;

	td->io_size = td->total_file_size;
	td->total_io_size = td->io_size;

	for_each_file(td, f, i) {
		f->file_size = td->total_file_size / td->nr_files;
		f->real_file_size = f->file_size;
	}

	return 0;
}

static struct ioengine_ops ioengine = {
	.name		= "net",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_netio_prep,
	.queue		= fio_netio_queue,
	.setup		= fio_netio_setup,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO | FIO_SELFOPEN,
};

static void fio_init fio_netio_register(void)
{
	register_ioengine(&ioengine);
}

static void fio_exit fio_netio_unregister(void)
{
	unregister_ioengine(&ioengine);
}
