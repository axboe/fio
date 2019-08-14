/*
 * net engine
 *
 * IO engine that reads/writes to/from sockets.
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "../fio.h"
#include "../verify.h"
#include "../optgroup.h"

struct netio_data {
	int listenfd;
	int use_splice;
	int seq_off;
	int pipes[2];
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	struct sockaddr_un addr_un;
	uint64_t udp_send_seq;
	uint64_t udp_recv_seq;
};

struct netio_options {
	struct thread_data *td;
	unsigned int port;
	unsigned int proto;
	unsigned int listen;
	unsigned int pingpong;
	unsigned int nodelay;
	unsigned int ttl;
	unsigned int window_size;
	unsigned int mss;
	char *intfc;
};

struct udp_close_msg {
	uint32_t magic;
	uint32_t cmd;
};

struct udp_seq {
	uint64_t magic;
	uint64_t seq;
	uint64_t bs;
};

enum {
	FIO_LINK_CLOSE = 0x89,
	FIO_LINK_OPEN_CLOSE_MAGIC = 0x6c696e6b,
	FIO_LINK_OPEN = 0x98,
	FIO_UDP_SEQ_MAGIC = 0x657375716e556563ULL,

	FIO_TYPE_TCP	= 1,
	FIO_TYPE_UDP	= 2,
	FIO_TYPE_UNIX	= 3,
	FIO_TYPE_TCP_V6	= 4,
	FIO_TYPE_UDP_V6	= 5,
};

static int str_hostname_cb(void *data, const char *input);
static struct fio_option options[] = {
	{
		.name	= "hostname",
		.lname	= "net engine hostname",
		.type	= FIO_OPT_STR_STORE,
		.cb	= str_hostname_cb,
		.help	= "Hostname for net IO engine",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "port",
		.lname	= "net engine port",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct netio_options, port),
		.minval	= 1,
		.maxval	= 65535,
		.help	= "Port to use for TCP or UDP net connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "protocol",
		.lname	= "net engine protocol",
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
#ifdef CONFIG_IPV6
			  { .ival = "tcpv6",
			    .oval = FIO_TYPE_TCP_V6,
			    .help = "Transmission Control Protocol V6",
			  },
#endif
			  { .ival = "udp",
			    .oval = FIO_TYPE_UDP,
			    .help = "User Datagram Protocol",
			  },
#ifdef CONFIG_IPV6
			  { .ival = "udpv6",
			    .oval = FIO_TYPE_UDP_V6,
			    .help = "User Datagram Protocol V6",
			  },
#endif
			  { .ival = "unix",
			    .oval = FIO_TYPE_UNIX,
			    .help = "UNIX domain socket",
			  },
		},
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
#ifdef CONFIG_TCP_NODELAY
	{
		.name	= "nodelay",
		.lname	= "No Delay",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct netio_options, nodelay),
		.help	= "Use TCP_NODELAY on TCP connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
#endif
	{
		.name	= "listen",
		.lname	= "net engine listen",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct netio_options, listen),
		.help	= "Listen for incoming TCP connections",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "pingpong",
		.lname	= "Ping Pong",
		.type	= FIO_OPT_STR_SET,
		.off1	= offsetof(struct netio_options, pingpong),
		.help	= "Ping-pong IO requests",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "interface",
		.lname	= "net engine interface",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct netio_options, intfc),
		.help	= "Network interface to use",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
	{
		.name	= "ttl",
		.lname	= "net engine multicast ttl",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct netio_options, ttl),
		.def    = "1",
		.minval	= 0,
		.help	= "Time-to-live value for outgoing UDP multicast packets",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
#ifdef CONFIG_NET_WINDOWSIZE
	{
		.name	= "window_size",
		.lname	= "Window Size",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct netio_options, window_size),
		.minval	= 0,
		.help	= "Set socket buffer window size",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
#endif
#ifdef CONFIG_NET_MSS
	{
		.name	= "mss",
		.lname	= "Maximum segment size",
		.type	= FIO_OPT_INT,
		.off1	= offsetof(struct netio_options, mss),
		.minval	= 0,
		.help	= "Set TCP maximum segment size",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_NETIO,
	},
#endif
	{
		.name	= NULL,
	},
};

static inline int is_udp(struct netio_options *o)
{
	return o->proto == FIO_TYPE_UDP || o->proto == FIO_TYPE_UDP_V6;
}

static inline int is_tcp(struct netio_options *o)
{
	return o->proto == FIO_TYPE_TCP || o->proto == FIO_TYPE_TCP_V6;
}

static inline int is_ipv6(struct netio_options *o)
{
	return o->proto == FIO_TYPE_UDP_V6 || o->proto == FIO_TYPE_TCP_V6;
}

static int set_window_size(struct thread_data *td, int fd)
{
#ifdef CONFIG_NET_WINDOWSIZE
	struct netio_options *o = td->eo;
	unsigned int wss;
	int snd, rcv, ret;

	if (!o->window_size)
		return 0;

	rcv = o->listen || o->pingpong;
	snd = !o->listen || o->pingpong;
	wss = o->window_size;
	ret = 0;

	if (rcv) {
		ret = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, (void *) &wss,
					sizeof(wss));
		if (ret < 0)
			td_verror(td, errno, "rcvbuf window size");
	}
	if (snd && !ret) {
		ret = setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (void *) &wss,
					sizeof(wss));
		if (ret < 0)
			td_verror(td, errno, "sndbuf window size");
	}

	return ret;
#else
	td_verror(td, -EINVAL, "setsockopt window size");
	return -1;
#endif
}

static int set_mss(struct thread_data *td, int fd)
{
#ifdef CONFIG_NET_MSS
	struct netio_options *o = td->eo;
	unsigned int mss;
	int ret;

	if (!o->mss || !is_tcp(o))
		return 0;

	mss = o->mss;
	ret = setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, (void *) &mss,
				sizeof(mss));
	if (ret < 0)
		td_verror(td, errno, "setsockopt TCP_MAXSEG");

	return ret;
#else
	td_verror(td, -EINVAL, "setsockopt TCP_MAXSEG");
	return -1;
#endif
}


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

static int fio_netio_is_multicast(const char *mcaddr)
{
	in_addr_t addr = inet_network(mcaddr);
	if (addr == -1)
		return 0;

	if (inet_network("224.0.0.0") <= addr &&
	    inet_network("239.255.255.255") >= addr)
		return 1;

	return 0;
}


static int fio_netio_prep(struct thread_data *td, struct io_u *io_u)
{
	struct netio_options *o = td->eo;

	/*
	 * Make sure we don't see spurious reads to a receiver, and vice versa
	 */
	if (is_tcp(o))
		return 0;

	if ((o->listen && io_u->ddir == DDIR_WRITE) ||
	    (!o->listen && io_u->ddir == DDIR_READ)) {
		td_verror(td, EINVAL, "bad direction");
		return 1;
	}

	return 0;
}

#ifdef CONFIG_LINUX_SPLICE
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
	struct netio_data *nd = td->io_ops_data;

	return splice_io_u(io_u->file->fd, nd->pipes[1], io_u->xfer_buflen);
}

/*
 * Transmit 'len' bytes from the internal pipe
 */
static int splice_out(struct thread_data *td, struct io_u *io_u,
		      unsigned int len)
{
	struct netio_data *nd = td->io_ops_data;

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
	struct netio_data *nd = td->io_ops_data;

	return vmsplice_io_u(io_u, nd->pipes[0], len);
}

/*
 * vmsplice() io_u to pipe
 */
static int vmsplice_io_u_in(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops_data;

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

static void store_udp_seq(struct netio_data *nd, struct io_u *io_u)
{
	struct udp_seq *us;

	if (io_u->xfer_buflen < sizeof(*us))
		return;

	us = io_u->xfer_buf + io_u->xfer_buflen - sizeof(*us);
	us->magic = cpu_to_le64((uint64_t) FIO_UDP_SEQ_MAGIC);
	us->bs = cpu_to_le64((uint64_t) io_u->xfer_buflen);
	us->seq = cpu_to_le64(nd->udp_send_seq++);
}

static void verify_udp_seq(struct thread_data *td, struct netio_data *nd,
			   struct io_u *io_u)
{
	struct udp_seq *us;
	uint64_t seq;

	if (io_u->xfer_buflen < sizeof(*us))
		return;

	if (nd->seq_off)
		return;

	us = io_u->xfer_buf + io_u->xfer_buflen - sizeof(*us);
	if (le64_to_cpu(us->magic) != FIO_UDP_SEQ_MAGIC)
		return;
	if (le64_to_cpu(us->bs) != io_u->xfer_buflen) {
		nd->seq_off = 1;
		return;
	}

	seq = le64_to_cpu(us->seq);

	if (seq != nd->udp_recv_seq)
		td->ts.drop_io_u[io_u->ddir] += seq - nd->udp_recv_seq;

	nd->udp_recv_seq = seq + 1;
}

static int fio_netio_send(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	int ret, flags = 0;

	do {
		if (is_udp(o)) {
			const struct sockaddr *to;
			socklen_t len;

			if (is_ipv6(o)) {
				to = (struct sockaddr *) &nd->addr6;
				len = sizeof(nd->addr6);
			} else {
				to = (struct sockaddr *) &nd->addr;
				len = sizeof(nd->addr);
			}

			if (td->o.verify == VERIFY_NONE)
				store_udp_seq(nd, io_u);

			ret = sendto(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags, to, len);
		} else {
			/*
			 * if we are going to write more, set MSG_MORE
			 */
#ifdef MSG_MORE
			if ((td->this_io_bytes[DDIR_WRITE] + io_u->xfer_buflen <
			    td->o.size) && !o->pingpong)
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
	} while (1);

	return ret;
}

static int is_close_msg(struct io_u *io_u, int len)
{
	struct udp_close_msg *msg;

	if (len != sizeof(struct udp_close_msg))
		return 0;

	msg = io_u->xfer_buf;
	if (le32_to_cpu(msg->magic) != FIO_LINK_OPEN_CLOSE_MAGIC)
		return 0;
	if (le32_to_cpu(msg->cmd) != FIO_LINK_CLOSE)
		return 0;

	return 1;
}

static int fio_netio_recv(struct thread_data *td, struct io_u *io_u)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	int ret, flags = 0;

	do {
		if (is_udp(o)) {
			struct sockaddr *from;
			socklen_t l, *len = &l;

			if (o->listen) {
				if (!is_ipv6(o)) {
					from = (struct sockaddr *) &nd->addr;
					*len = sizeof(nd->addr);
				} else {
					from = (struct sockaddr *) &nd->addr6;
					*len = sizeof(nd->addr6);
				}
			} else {
				from = NULL;
				len = NULL;
			}

			ret = recvfrom(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags, from, len);

			if (is_close_msg(io_u, ret)) {
				td->done = 1;
				return 0;
			}
		} else {
			ret = recv(io_u->file->fd, io_u->xfer_buf,
					io_u->xfer_buflen, flags);

			if (is_close_msg(io_u, ret)) {
				td->done = 1;
				return 0;
			}
		}
		if (ret > 0)
			break;
		else if (!ret && (flags & MSG_WAITALL))
			break;

		ret = poll_wait(td, io_u->file->fd, POLLIN);
		if (ret <= 0)
			break;
		flags |= MSG_WAITALL;
	} while (1);

	if (is_udp(o) && td->o.verify == VERIFY_NONE)
		verify_udp_seq(td, nd, io_u);

	return ret;
}

static enum fio_q_status __fio_netio_queue(struct thread_data *td,
					   struct io_u *io_u,
					   enum fio_ddir ddir)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	int ret;

	if (ddir == DDIR_WRITE) {
		if (!nd->use_splice || is_udp(o) ||
		    o->proto == FIO_TYPE_UNIX)
			ret = fio_netio_send(td, io_u);
		else
			ret = fio_netio_splice_out(td, io_u);
	} else if (ddir == DDIR_READ) {
		if (!nd->use_splice || is_udp(o) ||
		    o->proto == FIO_TYPE_UNIX)
			ret = fio_netio_recv(td, io_u);
		else
			ret = fio_netio_splice_in(td, io_u);
	} else
		ret = 0;	/* must be a SYNC */

	if (ret != (int) io_u->xfer_buflen) {
		if (ret > 0) {
			io_u->resid = io_u->xfer_buflen - ret;
			io_u->error = 0;
			return FIO_Q_COMPLETED;
		} else if (!ret)
			return FIO_Q_BUSY;
		else {
			int err = errno;

			if (ddir == DDIR_WRITE && err == EMSGSIZE)
				return FIO_Q_BUSY;

			io_u->error = err;
		}
	}

	if (io_u->error)
		td_verror(td, io_u->error, "xfer");

	return FIO_Q_COMPLETED;
}

static enum fio_q_status fio_netio_queue(struct thread_data *td,
					 struct io_u *io_u)
{
	struct netio_options *o = td->eo;
	int ret;

	fio_ro_check(td, io_u);

	ret = __fio_netio_queue(td, io_u, io_u->ddir);
	if (!o->pingpong || ret != FIO_Q_COMPLETED)
		return ret;

	/*
	 * For ping-pong mode, receive or send reply as needed
	 */
	if (td_read(td) && io_u->ddir == DDIR_READ)
		ret = __fio_netio_queue(td, io_u, DDIR_WRITE);
	else if (td_write(td) && io_u->ddir == DDIR_WRITE)
		ret = __fio_netio_queue(td, io_u, DDIR_READ);

	return ret;
}

static int fio_netio_connect(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	int type, domain;

	if (o->proto == FIO_TYPE_TCP) {
		domain = AF_INET;
		type = SOCK_STREAM;
	} else if (o->proto == FIO_TYPE_TCP_V6) {
		domain = AF_INET6;
		type = SOCK_STREAM;
	} else if (o->proto == FIO_TYPE_UDP) {
		domain = AF_INET;
		type = SOCK_DGRAM;
	} else if (o->proto == FIO_TYPE_UDP_V6) {
		domain = AF_INET6;
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

#ifdef CONFIG_TCP_NODELAY
	if (o->nodelay && is_tcp(o)) {
		int optval = 1;

		if (setsockopt(f->fd, IPPROTO_TCP, TCP_NODELAY, (void *) &optval, sizeof(int)) < 0) {
			log_err("fio: cannot set TCP_NODELAY option on socket (%s), disable with 'nodelay=0'\n", strerror(errno));
			return 1;
		}
	}
#endif

	if (set_window_size(td, f->fd)) {
		close(f->fd);
		return 1;
	}
	if (set_mss(td, f->fd)) {
		close(f->fd);
		return 1;
	}

	if (is_udp(o)) {
		if (!fio_netio_is_multicast(td->o.filename))
			return 0;
		if (is_ipv6(o)) {
			log_err("fio: multicast not supported on IPv6\n");
			close(f->fd);
			return 1;
		}

		if (o->intfc) {
			struct in_addr interface_addr;

			if (inet_aton(o->intfc, &interface_addr) == 0) {
				log_err("fio: interface not valid interface IP\n");
				close(f->fd);
				return 1;
			}
			if (setsockopt(f->fd, IPPROTO_IP, IP_MULTICAST_IF, (const char*)&interface_addr, sizeof(interface_addr)) < 0) {
				td_verror(td, errno, "setsockopt IP_MULTICAST_IF");
				close(f->fd);
				return 1;
			}
		}
		if (setsockopt(f->fd, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&o->ttl, sizeof(o->ttl)) < 0) {
			td_verror(td, errno, "setsockopt IP_MULTICAST_TTL");
			close(f->fd);
			return 1;
		}
		return 0;
	} else if (o->proto == FIO_TYPE_TCP) {
		socklen_t len = sizeof(nd->addr);

		if (connect(f->fd, (struct sockaddr *) &nd->addr, len) < 0) {
			td_verror(td, errno, "connect");
			close(f->fd);
			return 1;
		}
	} else if (o->proto == FIO_TYPE_TCP_V6) {
		socklen_t len = sizeof(nd->addr6);

		if (connect(f->fd, (struct sockaddr *) &nd->addr6, len) < 0) {
			td_verror(td, errno, "connect");
			close(f->fd);
			return 1;
		}

	} else {
		struct sockaddr_un *addr = &nd->addr_un;
		socklen_t len;

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
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	socklen_t socklen;
	int state;

	if (is_udp(o)) {
		f->fd = nd->listenfd;
		return 0;
	}

	state = td->runstate;
	td_set_runstate(td, TD_SETTING_UP);

	log_info("fio: waiting for connection\n");

	if (poll_wait(td, nd->listenfd, POLLIN) < 0)
		goto err;

	if (o->proto == FIO_TYPE_TCP) {
		socklen = sizeof(nd->addr);
		f->fd = accept(nd->listenfd, (struct sockaddr *) &nd->addr, &socklen);
	} else {
		socklen = sizeof(nd->addr6);
		f->fd = accept(nd->listenfd, (struct sockaddr *) &nd->addr6, &socklen);
	}

	if (f->fd < 0) {
		td_verror(td, errno, "accept");
		goto err;
	}

#ifdef CONFIG_TCP_NODELAY
	if (o->nodelay && is_tcp(o)) {
		int optval = 1;

		if (setsockopt(f->fd, IPPROTO_TCP, TCP_NODELAY, (void *) &optval, sizeof(int)) < 0) {
			log_err("fio: cannot set TCP_NODELAY option on socket (%s), disable with 'nodelay=0'\n", strerror(errno));
			return 1;
		}
	}
#endif

	reset_all_stats(td);
	td_set_runstate(td, state);
	return 0;
err:
	td_set_runstate(td, state);
	return 1;
}

static void fio_netio_send_close(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	struct udp_close_msg msg;
	struct sockaddr *to;
	socklen_t len;
	int ret;

	if (is_ipv6(o)) {
		to = (struct sockaddr *) &nd->addr6;
		len = sizeof(nd->addr6);
	} else {
		to = (struct sockaddr *) &nd->addr;
		len = sizeof(nd->addr);
	}

	msg.magic = cpu_to_le32((uint32_t) FIO_LINK_OPEN_CLOSE_MAGIC);
	msg.cmd = cpu_to_le32((uint32_t) FIO_LINK_CLOSE);

	ret = sendto(f->fd, (void *) &msg, sizeof(msg), MSG_WAITALL, to, len);
	if (ret < 0)
		td_verror(td, errno, "sendto udp link close");
}

static int fio_netio_close_file(struct thread_data *td, struct fio_file *f)
{
	/*
	 * Notify the receiver that we are closing down the link
	 */
	fio_netio_send_close(td, f);

	return generic_close_file(td, f);
}

static int fio_netio_udp_recv_open(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	struct udp_close_msg msg;
	struct sockaddr *to;
	socklen_t len;
	int ret;

	if (is_ipv6(o)) {
		len = sizeof(nd->addr6);
		to = (struct sockaddr *) &nd->addr6;
	} else {
		len = sizeof(nd->addr);
		to = (struct sockaddr *) &nd->addr;
	}

	ret = recvfrom(f->fd, (void *) &msg, sizeof(msg), MSG_WAITALL, to, &len);
	if (ret < 0) {
		td_verror(td, errno, "recvfrom udp link open");
		return ret;
	}

	if (ntohl(msg.magic) != FIO_LINK_OPEN_CLOSE_MAGIC ||
	    ntohl(msg.cmd) != FIO_LINK_OPEN) {
		log_err("fio: bad udp open magic %x/%x\n", ntohl(msg.magic),
								ntohl(msg.cmd));
		return -1;
	}

	fio_gettime(&td->start, NULL);
	return 0;
}

static int fio_netio_send_open(struct thread_data *td, struct fio_file *f)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	struct udp_close_msg msg;
	struct sockaddr *to;
	socklen_t len;
	int ret;

	if (is_ipv6(o)) {
		len = sizeof(nd->addr6);
		to = (struct sockaddr *) &nd->addr6;
	} else {
		len = sizeof(nd->addr);
		to = (struct sockaddr *) &nd->addr;
	}

	msg.magic = htonl(FIO_LINK_OPEN_CLOSE_MAGIC);
	msg.cmd = htonl(FIO_LINK_OPEN);

	ret = sendto(f->fd, (void *) &msg, sizeof(msg), MSG_WAITALL, to, len);
	if (ret < 0) {
		td_verror(td, errno, "sendto udp link open");
		return ret;
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

	if (ret) {
		f->fd = -1;
		return ret;
	}

	if (is_udp(o)) {
		if (td_write(td))
			ret = fio_netio_send_open(td, f);
		else {
			int state;

			state = td->runstate;
			td_set_runstate(td, TD_SETTING_UP);
			ret = fio_netio_udp_recv_open(td, f);
			td_set_runstate(td, state);
		}
	}

	if (ret)
		fio_netio_close_file(td, f);

	return ret;
}

static int fio_fill_addr(struct thread_data *td, const char *host, int af,
			 void *dst, struct addrinfo **res)
{
	struct netio_options *o = td->eo;
	struct addrinfo hints;
	int ret;

	if (inet_pton(af, host, dst))
		return 0;

	memset(&hints, 0, sizeof(hints));

	if (is_tcp(o))
		hints.ai_socktype = SOCK_STREAM;
	else
		hints.ai_socktype = SOCK_DGRAM;

	if (is_ipv6(o))
		hints.ai_family = AF_INET6;
	else
		hints.ai_family = AF_INET;

	ret = getaddrinfo(host, NULL, &hints, res);
	if (ret) {
		int e = EINVAL;
		char str[128];

		if (ret == EAI_SYSTEM)
			e = errno;

		snprintf(str, sizeof(str), "getaddrinfo: %s", gai_strerror(ret));
		td_verror(td, e, str);
		return 1;
	}

	return 0;
}

static int fio_netio_setup_connect_inet(struct thread_data *td,
					const char *host, unsigned short port)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	struct addrinfo *res = NULL;
	void *dst, *src;
	int af, len;

	if (!host) {
		log_err("fio: connect with no host to connect to.\n");
		if (td_read(td))
			log_err("fio: did you forget to set 'listen'?\n");

		td_verror(td, EINVAL, "no hostname= set");
		return 1;
	}

	nd->addr.sin_family = AF_INET;
	nd->addr.sin_port = htons(port);
	nd->addr6.sin6_family = AF_INET6;
	nd->addr6.sin6_port = htons(port);

	if (is_ipv6(o)) {
		af = AF_INET6;
		dst = &nd->addr6.sin6_addr;
	} else {
		af = AF_INET;
		dst = &nd->addr.sin_addr;
	}

	if (fio_fill_addr(td, host, af, dst, &res))
		return 1;

	if (!res)
		return 0;

	if (is_ipv6(o)) {
		len = sizeof(nd->addr6.sin6_addr);
		src = &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr;
	} else {
		len = sizeof(nd->addr.sin_addr);
		src = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
	}

	memcpy(dst, src, len);
	freeaddrinfo(res);
	return 0;
}

static int fio_netio_setup_connect_unix(struct thread_data *td,
					const char *path)
{
	struct netio_data *nd = td->io_ops_data;
	struct sockaddr_un *soun = &nd->addr_un;

	soun->sun_family = AF_UNIX;
	snprintf(soun->sun_path, sizeof(soun->sun_path), "%s", path);
	return 0;
}

static int fio_netio_setup_connect(struct thread_data *td)
{
	struct netio_options *o = td->eo;

	if (is_udp(o) || is_tcp(o))
		return fio_netio_setup_connect_inet(td, td->o.filename,o->port);
	else
		return fio_netio_setup_connect_unix(td, td->o.filename);
}

static int fio_netio_setup_listen_unix(struct thread_data *td, const char *path)
{
	struct netio_data *nd = td->io_ops_data;
	struct sockaddr_un *addr = &nd->addr_un;
	mode_t mode;
	int len, fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	mode = umask(000);

	addr->sun_family = AF_UNIX;
	snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", path);
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
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	struct ip_mreq mr;
	struct sockaddr_in sin;
	struct sockaddr *saddr;
	int fd, opt, type, domain;
	socklen_t len;

	memset(&sin, 0, sizeof(sin));

	if (o->proto == FIO_TYPE_TCP) {
		type = SOCK_STREAM;
		domain = AF_INET;
	} else if (o->proto == FIO_TYPE_TCP_V6) {
		type = SOCK_STREAM;
		domain = AF_INET6;
	} else if (o->proto == FIO_TYPE_UDP) {
		type = SOCK_DGRAM;
		domain = AF_INET;
	} else if (o->proto == FIO_TYPE_UDP_V6) {
		type = SOCK_DGRAM;
		domain = AF_INET6;
	} else {
		log_err("fio: unknown proto %d\n", o->proto);
		return 1;
	}

	fd = socket(domain, type, 0);
	if (fd < 0) {
		td_verror(td, errno, "socket");
		return 1;
	}

	opt = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *) &opt, sizeof(opt)) < 0) {
		td_verror(td, errno, "setsockopt");
		close(fd);
		return 1;
	}
#ifdef SO_REUSEPORT
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, (void *) &opt, sizeof(opt)) < 0) {
		td_verror(td, errno, "setsockopt");
		close(fd);
		return 1;
	}
#endif

	if (set_window_size(td, fd)) {
		close(fd);
		return 1;
	}
	if (set_mss(td, fd)) {
		close(fd);
		return 1;
	}

	if (td->o.filename) {
		if (!is_udp(o) || !fio_netio_is_multicast(td->o.filename)) {
			log_err("fio: hostname not valid for non-multicast inbound network IO\n");
			close(fd);
			return 1;
		}
		if (is_ipv6(o)) {
			log_err("fio: IPv6 not supported for multicast network IO\n");
			close(fd);
			return 1;
		}

		inet_aton(td->o.filename, &sin.sin_addr);

		mr.imr_multiaddr = sin.sin_addr;
		if (o->intfc) {
			if (inet_aton(o->intfc, &mr.imr_interface) == 0) {
				log_err("fio: interface not valid interface IP\n");
				close(fd);
				return 1;
			}
		} else {
			mr.imr_interface.s_addr = htonl(INADDR_ANY);
		}

		if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (const char*)&mr, sizeof(mr)) < 0) {
			td_verror(td, errno, "setsockopt IP_ADD_MEMBERSHIP");
			close(fd);
			return 1;
		}
	}

	if (!is_ipv6(o)) {
		saddr = (struct sockaddr *) &nd->addr;
		len = sizeof(nd->addr);

		nd->addr.sin_family = AF_INET;
		nd->addr.sin_addr.s_addr = sin.sin_addr.s_addr ? sin.sin_addr.s_addr : htonl(INADDR_ANY);
		nd->addr.sin_port = htons(port);
	} else {
		saddr = (struct sockaddr *) &nd->addr6;
		len = sizeof(nd->addr6);

		nd->addr6.sin6_family = AF_INET6;
		nd->addr6.sin6_addr = in6addr_any;
		nd->addr6.sin6_port = htons(port);
	}

	if (bind(fd, saddr, len) < 0) {
		close(fd);
		td_verror(td, errno, "bind");
		return 1;
	}

	nd->listenfd = fd;
	return 0;
}

static int fio_netio_setup_listen(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops_data;
	struct netio_options *o = td->eo;
	int ret;

	if (is_udp(o) || is_tcp(o))
		ret = fio_netio_setup_listen_inet(td, o->port);
	else
		ret = fio_netio_setup_listen_unix(td, td->o.filename);

	if (ret)
		return ret;
	if (is_udp(o))
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

	o->port += td->subjob_number;

	if (!is_tcp(o)) {
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

	if (o->listen)
		ret = fio_netio_setup_listen(td);
	else
		ret = fio_netio_setup_connect(td);

	return ret;
}

static void fio_netio_cleanup(struct thread_data *td)
{
	struct netio_data *nd = td->io_ops_data;

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
		add_file(td, td->o.filename ?: "net", 0, 0);
		td->o.nr_files = td->o.nr_files ?: 1;
		td->o.open_files++;
	}

	if (!td->io_ops_data) {
		nd = malloc(sizeof(*nd));

		memset(nd, 0, sizeof(*nd));
		nd->listenfd = -1;
		nd->pipes[0] = nd->pipes[1] = -1;
		td->io_ops_data = nd;
	}

	return 0;
}

static void fio_netio_terminate(struct thread_data *td)
{
	kill(td->pid, SIGTERM);
}

#ifdef CONFIG_LINUX_SPLICE
static int fio_netio_setup_splice(struct thread_data *td)
{
	struct netio_data *nd;

	fio_netio_setup(td);

	nd = td->io_ops_data;
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
	.close_file		= fio_netio_close_file,
	.terminate		= fio_netio_terminate,
	.options		= options,
	.option_struct_size	= sizeof(struct netio_options),
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
				  FIO_PIPEIO,
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
	.terminate		= fio_netio_terminate,
	.options		= options,
	.option_struct_size	= sizeof(struct netio_options),
	.flags			= FIO_SYNCIO | FIO_DISKLESSIO | FIO_UNIDIR |
				  FIO_PIPEIO | FIO_BIT_BASED,
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
#ifdef CONFIG_LINUX_SPLICE
	register_ioengine(&ioengine_splice);
#endif
}

static void fio_exit fio_netio_unregister(void)
{
	unregister_ioengine(&ioengine_rw);
#ifdef CONFIG_LINUX_SPLICE
	unregister_ioengine(&ioengine_splice);
#endif
}
