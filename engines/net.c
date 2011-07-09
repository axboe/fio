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
#include <sys/types.h>
#include <sys/socket.h>

#include "../fio.h"

struct netio_data {
	int listenfd;
	int send_to_net;
	int use_splice;
	int net_protocol;
	int pipes[2];
	char host[64];
	struct sockaddr_in addr;
};

struct udp_close_msg {
	uint32_t magic;
	uint32_t cmd;
};

enum {
	FIO_LINK_CLOSE = 0x89,
	FIO_LINK_CLOSE_MAGIC = 0x6c696e6b,
};

/*
 * Return -1 for error and 'nr events' for a positive number
 * of events
 */
static int poll_wait(struct thread_data *td, int fd, short events)
{
	struct pollfd pfd;
	int ret;

	while (!td->terminate) {
		pfd.fd = fd;
		pfd.events = events;
		ret = poll(&pfd, 1, -1);
		if (ret < 0) {
			if (errno == EINTR)
				break;

			td_verror(td, errno, "poll");
			return -1;
		} else if (!ret)
			continue;

		break;
	}

	if (pfd.revents & events)
		return 1;

	return -1;
}

static int fio_netio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;

	/*
	 * Make sure we don't see spurious reads to a receiver, and vice versa
	 */
	if ((nd->send_to_net && io_u->ddir == DDIR_READ) ||
	    (!nd->send_to_net && io_u->ddir == DDIR_WRITE)) {
		td_verror(td, EINVAL, "bad direction");
		return 1;
	}
		
	return 0;
}

#ifdef FIO_HAVE_SPLICE
static int splice_io_u(int fdin, int fdout, unsigned int len)
{
	int bytes = 0;

	while (len) {
		int ret = splice(fdin, NULL, fdout, NULL, len, 0);

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
 * Receive bytes from a socket and fill them into the internal pipe
 */
static int splice_in(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;

	return splice_io_u(io_u->file->fd, nd->pipes[1], io_u->xfer_buflen);
}

/*
 * Transmit 'len' bytes from the internal pipe
 */
static int splice_out(struct thread_data *td, struct io_u *io_u,
		      unsigned int len)
{
	struct netio_data *nd = td->io_ops->data;

	return splice_io_u(nd->pipes[0], io_u->file->fd, len);
}

static int vmsplice_io_u(struct io_u *io_u, int fd, unsigned int len)
{
	struct iovec iov = {
		.iov_base = io_u->xfer_buf,
		.iov_len = len,
	};
	int bytes = 0;

	while (iov.iov_len) {
		int ret = vmsplice(fd, &iov, 1, SPLICE_F_MOVE);

		if (ret < 0) {
			if (!bytes)
				bytes = ret;
			break;
		} else if (!ret)
			break;

		iov.iov_len -= ret;
		iov.iov_base += ret;
		bytes += ret;
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

	return vmsplice_io_u(io_u, nd->pipes[0], len);
}

/*
 * vmsplice() io_u to pipe
 */
static int vmsplice_io_u_in(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;

	return vmsplice_io_u(io_u, nd->pipes[1], io_u->xfer_buflen);
}

/*
 * splice receive - transfer socket data into a pipe using splice, then map
 * that pipe data into the io_u using vmsplice.
 */
static int fio_netio_splice_in(struct thread_data *td, struct io_u *io_u)
{
	int ret;

	ret = splice_in(td, io_u);
	if (ret > 0)
		return vmsplice_io_u_out(td, io_u, ret);

	return ret;
}

/*
 * splice transmit - map data from the io_u into a pipe by using vmsplice,
 * then transfer that pipe to a socket using splice.
 */
static int fio_netio_splice_out(struct thread_data *td, struct io_u *io_u)
{
	int ret;

	ret = vmsplice_io_u_in(td, io_u);
	if (ret > 0)
		return splice_out(td, io_u, ret);

	return ret;
}
#else
static int fio_netio_splice_in(struct thread_data *td, struct io_u *io_u)
{
	errno = EOPNOTSUPP;
	return -1;
}

static int fio_netio_splice_out(struct thread_data *td, struct io_u *io_u)
{
	errno = EOPNOTSUPP;
	return -1;
}
#endif

static int fio_netio_send(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	int ret, flags = OS_MSG_DONTWAIT;

	do {
		if (nd->net_protocol == IPPROTO_UDP) {
			struct sockaddr *to = (struct sockaddr *) &nd->addr;

			ret = sendto(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags, to,
					sizeof(*to));
		} else {
			/*
			 * if we are going to write more, set MSG_MORE
			 */
#ifdef MSG_MORE
			if (td->this_io_bytes[DDIR_WRITE] + io_u->xfer_buflen <
			    td->o.size)
				flags |= MSG_MORE;
#endif
			ret = send(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags);
		}
		if (ret > 0)
			break;

		ret = poll_wait(td, io_u->file->fd, POLLOUT);
		if (ret <= 0)
			break;

		flags &= ~OS_MSG_DONTWAIT;
	} while (1);

	return ret;
}

static int is_udp_close(struct io_u *io_u, int len)
{
	struct udp_close_msg *msg;

	if (len != sizeof(struct udp_close_msg))
		return 0;

	msg = io_u->xfer_buf;
	if (ntohl(msg->magic) != FIO_LINK_CLOSE_MAGIC)
		return 0;
	if (ntohl(msg->cmd) != FIO_LINK_CLOSE)
		return 0;

	return 1;
}

static int fio_netio_recv(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	int ret, flags = OS_MSG_DONTWAIT;

	do {
		if (nd->net_protocol == IPPROTO_UDP) {
#ifdef __hpux
			int len = sizeof(nd->addr);
#else
			socklen_t len = sizeof(nd->addr);
#endif
			struct sockaddr *from = (struct sockaddr *) &nd->addr;

			ret = recvfrom(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags, from, &len);
			if (is_udp_close(io_u, ret)) {
				td->done = 1;
				return 0;
			}
		} else {
			ret = recv(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags);
		}
		if (ret > 0)
			break;

		ret = poll_wait(td, io_u->file->fd, POLLIN);
		if (ret <= 0)
			break;
		flags &= ~OS_MSG_DONTWAIT;
		flags |= MSG_WAITALL;
	} while (1);

	return ret;
}

static int fio_netio_queue(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops->data;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE) {
		if (!nd->use_splice || nd->net_protocol == IPPROTO_UDP)
			ret = fio_netio_send(td, io_u);
		else
			ret = fio_netio_splice_out(td, io_u);
	} else if (io_u->ddir == DDIR_READ) {
		if (!nd->use_splice || nd->net_protocol == IPPROTO_UDP)
			ret = fio_netio_recv(td, io_u);
		else
			ret = fio_netio_splice_in(td, io_u);
	} else
		ret = 0;	/* must be a SYNC */

	if (ret != (int) io_u->xfer_buflen) {
		if (ret >= 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else {
			int err = errno;

			if (io_u->ddir == DDIR_WRITE && err == EMSGSIZE)
				return FIO_Q_BUSY;

			io_u->error = err;
		}
	}

	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

static int fio_netio_connect(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;
	int type;

	if (nd->net_protocol == IPPROTO_TCP)
		type = SOCK_STREAM;
	else
		type = SOCK_DGRAM;

	f->fd = socket(AF_INET, type, nd->net_protocol);
	if (f->fd < 0) {
		td_verror(td, errno, "socket");
		return 1;
	}

	if (nd->net_protocol == IPPROTO_UDP)
		return 0;

	if (connect(f->fd, (struct sockaddr *) &nd->addr, sizeof(nd->addr)) < 0) {
		td_verror(td, errno, "connect");
		return 1;
	}

	return 0;
}

static int fio_netio_accept(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;
#ifdef __hpux
	int socklen = sizeof(nd->addr);
#else
	socklen_t socklen = sizeof(nd->addr);
#endif

	if (nd->net_protocol == IPPROTO_UDP) {
		f->fd = nd->listenfd;
		return 0;
	}

	log_info("fio: waiting for connection\n");

	if (poll_wait(td, nd->listenfd, POLLIN) < 0)
		return 1;

	f->fd = accept(nd->listenfd, (struct sockaddr *) &nd->addr, &socklen);
	if (f->fd < 0) {
		td_verror(td, errno, "accept");
		return 1;
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

static void fio_netio_udp_close(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;
	struct udp_close_msg msg;
	struct sockaddr *to = (struct sockaddr *) &nd->addr;
	int ret;

	msg.magic = htonl(FIO_LINK_CLOSE_MAGIC);
	msg.cmd = htonl(FIO_LINK_CLOSE);

	ret = sendto(f->fd, &msg, sizeof(msg), MSG_WAITALL, to,
			sizeof(nd->addr));
	if (ret < 0)
		td_verror(td, errno, "sendto udp link close");
}

static int fio_netio_close_file(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;

	/*
	 * If this is an UDP connection, notify the receiver that we are
	 * closing down the link
	 */
	if (nd->net_protocol == IPPROTO_UDP)
		fio_netio_udp_close(td, f);

	return generic_close_file(td, f);
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
	int fd, opt, type;

	if (nd->net_protocol == IPPROTO_TCP)
		type = SOCK_STREAM;
	else
		type = SOCK_DGRAM;

	fd = socket(AF_INET, type, nd->net_protocol);
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
	if (nd->net_protocol == IPPROTO_TCP && listen(fd, 1) < 0) {
		td_verror(td, errno, "listen");
		return 1;
	}

	nd->listenfd = fd;
	return 0;
}

static int fio_netio_init(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops->data;
	unsigned int port;
	char host[64], buf[128];
	char *sep, *portp, *modep;
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
	if (!sep)
		goto bad_host;

	*sep = '\0';
	sep++;
	strcpy(host, buf);
	if (!strlen(host))
		goto bad_host;

	modep = NULL;
	portp = sep;
	sep = strchr(portp, '/');
	if (sep) {
		*sep = '\0';
		modep = sep + 1;
	}
		
	port = strtol(portp, NULL, 10);
	if (!port || port > 65535)
		goto bad_host;

	if (modep) {
		if (!strncmp("tcp", modep, strlen(modep)) ||
		    !strncmp("TCP", modep, strlen(modep)))
			nd->net_protocol = IPPROTO_TCP;
		else if (!strncmp("udp", modep, strlen(modep)) ||
			 !strncmp("UDP", modep, strlen(modep)))
			nd->net_protocol = IPPROTO_UDP;
		else
			goto bad_host;
	} else
		nd->net_protocol = IPPROTO_TCP;

	if (td_read(td)) {
		nd->send_to_net = 0;
		ret = fio_netio_setup_listen(td, port);
	} else {
		nd->send_to_net = 1;
		ret = fio_netio_setup_connect(td, host, port);
	}

	return ret;
bad_host:
	log_err("fio: bad network host/port/protocol: %s\n", td->o.filename);
	return 1;
}

static void fio_netio_cleanup(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops->data;

	if (nd) {
		if (nd->listenfd != -1)
			close(nd->listenfd);
		if (nd->pipes[0] != -1)
			close(nd->pipes[0]);
		if (nd->pipes[1] != -1)
			close(nd->pipes[1]);

		free(nd);
	}
}

static int fio_netio_setup(struct thread_data *td)
{
	struct netio_data *nd;

	if (!td->io_ops->data) {
		nd = malloc(sizeof(*nd));;

		memset(nd, 0, sizeof(*nd));
		nd->listenfd = -1;
		nd->pipes[0] = nd->pipes[1] = -1;
		td->io_ops->data = nd;
	}

	return 0;
}

#ifdef FIO_HAVE_SPLICE
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
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
			  FIO_SIGTERM | FIO_PIPEIO,
};
#endif

static struct ioengine_ops ioengine_rw = {
	.name		= "net",
	.version	= FIO_IOOPS_VERSION,
	.prep		= fio_netio_prep,
	.queue		= fio_netio_queue,
	.setup		= fio_netio_setup,
	.init		= fio_netio_init,
	.cleanup	= fio_netio_cleanup,
	.open_file	= fio_netio_open_file,
	.close_file	= fio_netio_close_file,
	.flags		= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
			  FIO_SIGTERM | FIO_PIPEIO,
};

static void fio_init fio_netio_register(void)
{
	register_ioengine(&ioengine_rw);
#ifdef FIO_HAVE_SPLICE
	register_ioengine(&ioengine_splice);
#endif
}

static void fio_exit fio_netio_unregister(void)
{
	unregister_ioengine(&ioengine_rw);
#ifdef FIO_HAVE_SPLICE
	unregister_ioengine(&ioengine_splice);
#endif
}
