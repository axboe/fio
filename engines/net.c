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
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../fio.h"

struct netio_data {
	int listenfd;
	int use_splice;
	int pipes[2];
	struct sockaddr_in addr;
	struct sockaddr_un addr_un;
};

struct netio_options {
	struct thread_data *td;
	unsigned int port;
	unsigned int proto;
	unsigned int listen;
};

struct udp_close_msg {
	uint32_t magic;
	uint32_t cmd;
};

enum {
	FIO_LINK_CLOSE = 0x89,
	FIO_LINK_CLOSE_MAGIC = 0x6c696e6b,

	FIO_TYPE_TCP	= 1,
	FIO_TYPE_UDP	= 2,
	FIO_TYPE_UNIX	= 3,
};

static int str_hostname_cb(void *data, const char *input);
static struct fio_option options[] = {
	{
		.name	= "hostname",
		.type	= FIO_OPT_STR_STORE,
		.cb	= str_hostname_cb,
		.help	= "Hostname for net IO engine",
	},
	{
		.name	= "port",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct netio_options, port),
		.minval	= 1,
		.maxval	= 65535,
		.help	= "Port to use for TCP or UDP net connections",
	},
	{
		.name	= "protocol",
		.alias	= "proto",
		.type	= FIO_OPT_STR,
		.off1	= offsetof(struct netio_options, proto),
		.help	= "Network protocol to use",
		.def	= "tcp",
		.posval = {
			  { .ival = "tcp",
			    .oval = FIO_TYPE_TCP,
			    .help = "Transmission Control Protocol",
			  },
			  { .ival = "udp",
			    .oval = FIO_TYPE_UDP,
			    .help = "User Datagram Protocol",
			  },
			  { .ival = "unix",
			    .oval = FIO_TYPE_UNIX,
			    .help = "UNIX domain socket",
			  },
		},
	},
	{
		.name	= "listen",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct netio_options, listen),
		.help	= "Listen for incoming TCP connections",
	},
	{
		.name	= NULL,
	},
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
	struct netio_options *o = td->eo;

	/*
	 * Make sure we don't see spurious reads to a receiver, and vice versa
	 */
	if (o->proto == FIO_TYPE_TCP)
		return 0;

	if ((o->listen && io_u->ddir == DDIR_WRITE) ||
	    (!o->listen && io_u->ddir == DDIR_READ)) {
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
	struct netio_options *o = td->eo;
	int ret, flags = OS_MSG_DONTWAIT;

	do {
		if (o->proto == FIO_TYPE_UDP) {
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
	struct netio_options *o = td->eo;
	int ret, flags = OS_MSG_DONTWAIT;

	do {
		if (o->proto == FIO_TYPE_UDP) {
			fio_socklen_t len = sizeof(nd->addr);
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
	struct netio_options *o = td->eo;
	int ret;

	fio_ro_check(td, io_u);

	if (io_u->ddir == DDIR_WRITE) {
		if (!nd->use_splice || o->proto == FIO_TYPE_UDP ||
		    o->proto == FIO_TYPE_UNIX)
			ret = fio_netio_send(td, io_u);
		else
			ret = fio_netio_splice_out(td, io_u);
	} else if (io_u->ddir == DDIR_READ) {
		if (!nd->use_splice || o->proto == FIO_TYPE_UDP ||
		    o->proto == FIO_TYPE_UNIX)
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
	struct netio_options *o = td->eo;
	int type, domain;

	if (o->proto == FIO_TYPE_TCP) {
		domain = AF_INET;
		type = SOCK_STREAM;
	} else if (o->proto == FIO_TYPE_UDP) {
		domain = AF_INET;
		type = SOCK_DGRAM;
	} else if (o->proto == FIO_TYPE_UNIX) {
		domain = AF_UNIX;
		type = SOCK_STREAM;
	} else {
		log_err("fio: bad network type %d\n", o->proto);
		f->fd = -1;
		return 1;
	}

	f->fd = socket(domain, type, 0);
	if (f->fd < 0) {
		td_verror(td, errno, "socket");
		return 1;
	}

	if (o->proto == FIO_TYPE_UDP)
		return 0;
	else if (o->proto == FIO_TYPE_TCP) {
		fio_socklen_t len = sizeof(nd->addr);

		if (connect(f->fd, (struct sockaddr *) &nd->addr, len) < 0) {
			td_verror(td, errno, "connect");
			close(f->fd);
			return 1;
		}
	} else {
		struct sockaddr_un *addr = &nd->addr_un;
		fio_socklen_t len;

		len = sizeof(addr->sun_family) + strlen(addr->sun_path) + 1;

		if (connect(f->fd, (struct sockaddr *) addr, len) < 0) {
			td_verror(td, errno, "connect");
			close(f->fd);
			return 1;
		}
	}

	return 0;
}

static int fio_netio_accept(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops->data;
	struct netio_options *o = td->eo;
	fio_socklen_t socklen = sizeof(nd->addr);

	if (o->proto == FIO_TYPE_UDP) {
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
	int ret;
	struct netio_options *o = td->eo;

	if (o->listen)
		ret = fio_netio_accept(td, f);
	else
		ret = fio_netio_connect(td, f);

	if (ret)
		f->fd = -1;
	return ret;
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
	struct netio_options *o = td->eo;

	/*
	 * If this is an UDP connection, notify the receiver that we are
	 * closing down the link
	 */
	if (o->proto == FIO_TYPE_UDP)
		fio_netio_udp_close(td, f);

	return generic_close_file(td, f);
}

static int fio_netio_setup_connect_inet(struct thread_data *td,
					const char *host, unsigned short port)
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

static int fio_netio_setup_connect_unix(struct thread_data *td,
					const char *path)
{
	struct netio_data *nd = td->io_ops->data;
	struct sockaddr_un *soun = &nd->addr_un;

	soun->sun_family = AF_UNIX;
	strcpy(soun->sun_path, path);
	return 0;
}

static int fio_netio_setup_connect(struct thread_data *td)
{
	struct netio_options *o = td->eo;

	if (o->proto == FIO_TYPE_UDP || o->proto == FIO_TYPE_TCP)
		return fio_netio_setup_connect_inet(td, td->o.filename,o->port);
	else
		return fio_netio_setup_connect_unix(td, td->o.filename);
}

static int fio_netio_setup_listen_unix(struct thread_data *td, const char *path)
{
	struct netio_data *nd = td->io_ops->data;
	struct sockaddr_un *addr = &nd->addr_un;
	mode_t mode;
	int len, fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	mode = umask(000);

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	strcpy(addr->sun_path, path);
	unlink(path);

	len = sizeof(addr->sun_family) + strlen(path) + 1;

	if (bind(fd, (struct sockaddr *) addr, len) < 0) {
		log_err("fio: bind: %s\n", strerror(errno));
		close(fd);
		return -1;
	}

	umask(mode);
	nd->listenfd = fd;
	return 0;
}

static int fio_netio_setup_listen_inet(struct thread_data *td, short port)
{
	struct netio_data *nd = td->io_ops->data;
	struct netio_options *o = td->eo;
	int fd, opt, type;

	if (o->proto == FIO_TYPE_TCP)
		type = SOCK_STREAM;
	else
		type = SOCK_DGRAM;

	fd = socket(AF_INET, type, 0);
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

	nd->listenfd = fd;
	return 0;
}

static int fio_netio_setup_listen(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops->data;
	struct netio_options *o = td->eo;
	int ret;

	if (o->proto == FIO_TYPE_UDP || o->proto == FIO_TYPE_TCP)
		ret = fio_netio_setup_listen_inet(td, o->port);
	else
		ret = fio_netio_setup_listen_unix(td, td->o.filename);

	if (ret)
		return ret;
	if (o->proto == FIO_TYPE_UDP)
		return 0;

	if (listen(nd->listenfd, 10) < 0) {
		td_verror(td, errno, "listen");
		nd->listenfd = -1;
		return 1;
	}

	return 0;
}

static int fio_netio_init(struct thread_data *td)
{
	struct netio_options *o = td->eo;
	int ret;

#ifdef WIN32
	WSADATA wsd;
	WSAStartup(MAKEWORD(2,2), &wsd);
#endif

	if (td_random(td)) {
		log_err("fio: network IO can't be random\n");
		return 1;
	}

	if (o->proto == FIO_TYPE_UNIX && o->port) {
		log_err("fio: network IO port not valid with unix socket\n");
		return 1;
	} else if (o->proto != FIO_TYPE_UNIX && !o->port) {
		log_err("fio: network IO requires port for tcp or udp\n");
		return 1;
	}

	if (o->proto != FIO_TYPE_TCP) {
		if (o->listen) {
			log_err("fio: listen only valid for TCP proto IO\n");
			return 1;
		}
		if (td_rw(td)) {
			log_err("fio: datagram network connections must be"
				   " read OR write\n");
			return 1;
		}
		if (o->proto == FIO_TYPE_UNIX && !td->o.filename) {
			log_err("fio: UNIX sockets need host/filename\n");
			return 1;
		}
		o->listen = td_read(td);
	}

	if (o->proto != FIO_TYPE_UNIX && o->listen && td->o.filename) {
		log_err("fio: hostname not valid for inbound network IO\n");
		return 1;
	}

	if (o->listen)
		ret = fio_netio_setup_listen(td);
	else
		ret = fio_netio_setup_connect(td);

	return ret;
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

	if (!td->files_index) {
		add_file(td, td->o.filename ?: "net");
		td->o.nr_files = td->o.nr_files ?: 1;
	}

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
	.name			= "netsplice",
	.version		= FIO_IOOPS_VERSION,
	.prep			= fio_netio_prep,
	.queue			= fio_netio_queue,
	.setup			= fio_netio_setup_splice,
	.init			= fio_netio_init,
	.cleanup		= fio_netio_cleanup,
	.open_file		= fio_netio_open_file,
	.close_file		= generic_close_file,
	.options		= options,
	.option_struct_size	= sizeof(struct netio_options),
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
				  FIO_SIGTERM | FIO_PIPEIO,
};
#endif

static struct ioengine_ops ioengine_rw = {
	.name			= "net",
	.version		= FIO_IOOPS_VERSION,
	.prep			= fio_netio_prep,
	.queue			= fio_netio_queue,
	.setup			= fio_netio_setup,
	.init			= fio_netio_init,
	.cleanup		= fio_netio_cleanup,
	.open_file		= fio_netio_open_file,
	.close_file		= fio_netio_close_file,
	.options		= options,
	.option_struct_size	= sizeof(struct netio_options),
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
				  FIO_SIGTERM | FIO_PIPEIO,
};

static int str_hostname_cb(void *data, const char *input)
{
	struct netio_options *o = data;

	if (o->td->o.filename)
		free(o->td->o.filename);
	o->td->o.filename = strdup(input);
	return 0;
}

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
