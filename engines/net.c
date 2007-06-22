/*
 * net engine
 *
 * IO engine that reads/writes to/from sockets.
 *
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

struct netio_data {
	int listenfd;
	int send_to_net;
	int use_splice;
	int pipes[2];
	char host[64];
	struct sockaddr_in addr;
};

static int fio_netio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	struct fio_file *f = io_u->file;

	/*
	 * Make sure we don't see spurious reads to a receiver, and vice versa
	 */
	if ((nd->send_to_net && io_u->ddir == DDIR_READ) ||
	    (!nd->send_to_net && io_u->ddir == DDIR_WRITE)) {
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

/*
 * Receive bytes from a socket and fill them into the internal pipe
 */
static int splice_in(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	unsigned int len = io_u->xfer_buflen;
	struct fio_file *f = io_u->file;
	int bytes = 0;

	while (len) {
		int ret = splice(f->fd, NULL, nd->pipes[1], NULL, len, 0);

		if (ret < 0) {
			if (!bytes)
				bytes = ret;

			break;
		} else if (!ret)
			break;

		bytes += ret;
		len -= ret;
	}

	return bytes;
}

/*
 * Transmit 'len' bytes from the internal pipe
 */
static int splice_out(struct thread_data *td, struct io_u *io_u,
		      unsigned int len)
{
	struct netio_data *nd = td->io_ops->data;
	struct fio_file *f = io_u->file;
	int bytes = 0;

	while (len) {
		int ret = splice(nd->pipes[0], NULL, f->fd, NULL, len, 0);

		if (ret < 0) {
			if (!bytes)
				bytes = ret;
			
			break;
		} else if (!ret)
			break;

		bytes += ret;
		len -= ret;
	}

	return bytes;
}

/*
 * vmsplice() pipe to io_u buffer
 */
static int vmsplice_io_u_out(struct thread_data *td, struct io_u *io_u,
			     unsigned int len)
{
	struct netio_data *nd = td->io_ops->data;
	struct iovec iov = {
		.iov_base = io_u->xfer_buf,
		.iov_len = len,
	};
	int bytes = 0;

	while (iov.iov_len) {
		int ret = vmsplice(nd->pipes[0], &iov, 1, 0);

		if (ret < 0) {
			if (!bytes)
				bytes = ret;
			break;
		} else if (!ret)
			break;

		iov.iov_len -= ret;
		bytes += ret;
		if (iov.iov_len)
			iov.iov_base += ret;
	}

	return bytes;
}

/*
 * vmsplice() io_u to pipe
 */
static int vmsplice_io_u_in(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	struct iovec iov = {
		.iov_base = io_u->xfer_buf,
		.iov_len = io_u->xfer_buflen,
	};
	unsigned int bytes = 0;

	while (iov.iov_len) {
		int ret = vmsplice(nd->pipes[1], &iov, 1, 0);

		if (ret < 0)
			return -1;
		else if (!ret)
			return bytes;

		iov.iov_len -= ret;
		bytes += ret;
		if (iov.iov_len)
			iov.iov_base += ret;
	}

	return bytes;
}

static int fio_netio_splice_in(struct thread_data *td, struct io_u *io_u)
{
	int ret;

	ret = splice_in(td, io_u);
	if (ret <= 0)
		return ret;

	return vmsplice_io_u_out(td, io_u, ret);
}

static int fio_netio_splice_out(struct thread_data *td, struct io_u *io_u)
{
	int ret;

	ret = vmsplice_io_u_in(td, io_u);
	if (ret <= 0)
		return ret;

	return splice_out(td, io_u, ret);
}

static int fio_netio_send(struct thread_data *td, struct io_u *io_u)
{
	int flags = 0;

	/*
	 * if we are going to write more, set MSG_MORE
	 */
	if (td->this_io_bytes[DDIR_WRITE] + io_u->xfer_buflen < td->o.size)
		flags = MSG_MORE;

	return send(io_u->file->fd, io_u->xfer_buf, io_u->xfer_buflen, flags);
}

static int fio_netio_recv(struct io_u *io_u)
{
	int flags = MSG_WAITALL;

	return recv(io_u->file->fd, io_u->xfer_buf, io_u->xfer_buflen, flags);
}

static int fio_netio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	int ret;

	if (io_u->ddir == DDIR_WRITE) {
		if (nd->use_splice)
			ret = fio_netio_splice_out(td, io_u);
		else
			ret = fio_netio_send(td, io_u);
	} else if (io_u->ddir == DDIR_READ) {
		if (nd->use_splice)
			ret = fio_netio_splice_in(td, io_u);
		else
			ret = fio_netio_recv(io_u);
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

static int fio_netio_connect(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;

	f->fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (f->fd < 0) {
		td_verror(td, errno, "socket");
		return 1;
	}

	if (connect(f->fd, (struct sockaddr *) &nd->addr, sizeof(nd->addr)) < 0) {
		td_verror(td, errno, "connect");
		return 1;
	}

	return 0;
}

static int fio_netio_accept(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;
	socklen_t socklen = sizeof(nd->addr);
	struct pollfd pfd;
	int ret;

	log_info("fio: waiting for connection\n");

	/*
	 * Accept loop. poll for incoming events, accept them. Repeat until we
	 * have all connections.
	 */
	while (!td->terminate) {
		pfd.fd = nd->listenfd;
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

		f->fd = accept(nd->listenfd, (struct sockaddr *) &nd->addr, &socklen);
		if (f->fd < 0) {
			td_verror(td, errno, "accept");
			return 1;
		}
		break;
	}

	return 0;
}


static int fio_netio_open_file(struct thread_data *td, struct fio_file *f)
{
	if (td_read(td))
		return fio_netio_accept(td, f);
	else
		return fio_netio_connect(td, f);
}

static int fio_netio_setup_connect(struct thread_data *td, const char *host,
				   unsigned short port)
{
	struct netio_data *nd = td->io_ops->data;

	nd->addr.sin_family = AF_INET;
	nd->addr.sin_port = htons(port);

	if (inet_aton(host, &nd->addr.sin_addr) != 1) {
		struct hostent *hent;

		hent = gethostbyname(host);
		if (!hent) {
			td_verror(td, errno, "gethostbyname");
			return 1;
		}

		memcpy(&nd->addr.sin_addr, hent->h_addr, 4);
	}

	return 0;
}

static int fio_netio_setup_listen(struct thread_data *td, short port)
{
	struct netio_data *nd = td->io_ops->data;
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

	nd->addr.sin_family = AF_INET;
	nd->addr.sin_addr.s_addr = htonl(INADDR_ANY);
	nd->addr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *) &nd->addr, sizeof(nd->addr)) < 0) {
		td_verror(td, errno, "bind");
		return 1;
	}
	if (listen(fd, 1) < 0) {
		td_verror(td, errno, "listen");
		return 1;
	}

	nd->listenfd = fd;
	return 0;
}

static int fio_netio_init(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops->data;
	unsigned short port;
	char host[64], buf[128];
	char *sep;
	int ret;

	if (td_rw(td)) {
		log_err("fio: network connections must be read OR write\n");
		return 1;
	}
	if (td_random(td)) {
		log_err("fio: network IO can't be random\n");
		return 1;
	}

	strcpy(buf, td->o.filename);

	sep = strchr(buf, '/');
	if (!sep) {
		log_err("fio: bad network host/port <<%s>>\n", td->o.filename);
		return 1;
	}

	*sep = '\0';
	sep++;
	strcpy(host, buf);
	port = atoi(sep);

	if (td_read(td)) {
		nd->send_to_net = 0;
		ret = fio_netio_setup_listen(td, port);
	} else {
		nd->send_to_net = 1;
		ret = fio_netio_setup_connect(td, host, port);
	}

	return ret;
}

static void fio_netio_cleanup(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops->data;

	if (nd) {
		free(nd);
		td->io_ops->data = NULL;
	}
}

static int fio_netio_setup(struct thread_data *td)
{
	struct netio_data *nd;

	if (!td->io_ops->data) {
		nd = malloc(sizeof(*nd));;

		memset(nd, 0, sizeof(*nd));
		nd->listenfd = -1;
		td->io_ops->data = nd;
	}

	return 0;
}

static int fio_netio_setup_splice(struct thread_data *td)
{
	struct netio_data *nd;

	fio_netio_setup(td);

	nd = td->io_ops->data;
	if (nd) {
		if (pipe(nd->pipes) < 0)
			return 1;

		nd->use_splice = 1;
		return 0;
	}

	return 1;
}

static struct ioengine_ops ioengine_rw = {
	.name		= "net",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_netio_prep,
	.queue		= fio_netio_queue,
	.setup		= fio_netio_setup,
	.init		= fio_netio_init,
	.cleanup	= fio_netio_cleanup,
	.open_file	= fio_netio_open_file,
	.close_file	= generic_close_file,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO,
};

static struct ioengine_ops ioengine_splice = {
	.name		= "netsplice",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_netio_prep,
	.queue		= fio_netio_queue,
	.setup		= fio_netio_setup_splice,
	.init		= fio_netio_init,
	.cleanup	= fio_netio_cleanup,
	.open_file	= fio_netio_open_file,
	.close_file	= generic_close_file,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO,
};

static void fio_init fio_netio_register(void)
{
	register_ioengine(&ioengine_rw);
	register_ioengine(&ioengine_splice);
}

static void fio_exit fio_netio_unregister(void)
{
	unregister_ioengine(&ioengine_rw);
	unregister_ioengine(&ioengine_splice);
}
