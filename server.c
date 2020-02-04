#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#ifdef CONFIG_ZLIB
#include <zlib.h>
#endif

#include "fio.h"
#include "options.h"
#include "server.h"
#include "crc/crc16.h"
#include "lib/ieee754.h"
#include "verify-state.h"
#include "smalloc.h"

int fio_net_port = FIO_NET_PORT;

bool exit_backend = false;

enum {
	SK_F_FREE	= 1,
	SK_F_COPY	= 2,
	SK_F_SIMPLE	= 4,
	SK_F_VEC	= 8,
	SK_F_INLINE	= 16,
};

struct sk_entry {
	struct flist_head list;	/* link on sk_out->list */
	int flags;		/* SK_F_* */
	int opcode;		/* Actual command fields */
	void *buf;
	off_t size;
	uint64_t tag;
	struct flist_head next;	/* Other sk_entry's, if linked command */
};

static char *fio_server_arg;
static char *bind_sock;
static struct sockaddr_in saddr_in;
static struct sockaddr_in6 saddr_in6;
static int use_ipv6;
#ifdef CONFIG_ZLIB
static unsigned int has_zlib = 1;
#else
static unsigned int has_zlib = 0;
#endif
static unsigned int use_zlib;
static char me[128];

static pthread_key_t sk_out_key;

struct fio_fork_item {
	struct flist_head list;
	int exitval;
	int signal;
	int exited;
	pid_t pid;
};

struct cmd_reply {
	struct fio_sem lock;
	void *data;
	size_t size;
	int error;
};

static const char *fio_server_ops[FIO_NET_CMD_NR] = {
	"",
	"QUIT",
	"EXIT",
	"JOB",
	"JOBLINE",
	"TEXT",
	"TS",
	"GS",
	"SEND_ETA",
	"ETA",
	"PROBE",
	"START",
	"STOP",
	"DISK_UTIL",
	"SERVER_START",
	"ADD_JOB",
	"RUN",
	"IOLOG",
	"UPDATE_JOB",
	"LOAD_FILE",
	"VTRIGGER",
	"SENDFILE",
	"JOB_OPT",
};

static void sk_lock(struct sk_out *sk_out)
{
	fio_sem_down(&sk_out->lock);
}

static void sk_unlock(struct sk_out *sk_out)
{
	fio_sem_up(&sk_out->lock);
}

void sk_out_assign(struct sk_out *sk_out)
{
	if (!sk_out)
		return;

	sk_lock(sk_out);
	sk_out->refs++;
	sk_unlock(sk_out);
	pthread_setspecific(sk_out_key, sk_out);
}

static void sk_out_free(struct sk_out *sk_out)
{
	__fio_sem_remove(&sk_out->lock);
	__fio_sem_remove(&sk_out->wait);
	__fio_sem_remove(&sk_out->xmit);
	sfree(sk_out);
}

static int __sk_out_drop(struct sk_out *sk_out)
{
	if (sk_out) {
		int refs;

		sk_lock(sk_out);
		assert(sk_out->refs != 0);
		refs = --sk_out->refs;
		sk_unlock(sk_out);

		if (!refs) {
			sk_out_free(sk_out);
			pthread_setspecific(sk_out_key, NULL);
			return 0;
		}
	}

	return 1;
}

void sk_out_drop(void)
{
	struct sk_out *sk_out;

	sk_out = pthread_getspecific(sk_out_key);
	__sk_out_drop(sk_out);
}

static void __fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
			       uint32_t pdu_len, uint64_t tag)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->version	= __cpu_to_le16(FIO_SERVER_VER);
	cmd->opcode	= cpu_to_le16(opcode);
	cmd->tag	= cpu_to_le64(tag);
	cmd->pdu_len	= cpu_to_le32(pdu_len);
}


static void fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
			     const void *pdu, uint32_t pdu_len, uint64_t tag)
{
	__fio_init_net_cmd(cmd, opcode, pdu_len, tag);

	if (pdu)
		memcpy(&cmd->payload, pdu, pdu_len);
}

const char *fio_server_op(unsigned int op)
{
	static char buf[32];

	if (op < FIO_NET_CMD_NR)
		return fio_server_ops[op];

	sprintf(buf, "UNKNOWN/%d", op);
	return buf;
}

static ssize_t iov_total_len(const struct iovec *iov, int count)
{
	ssize_t ret = 0;

	while (count--) {
		ret += iov->iov_len;
		iov++;
	}

	return ret;
}

static int fio_sendv_data(int sk, struct iovec *iov, int count)
{
	ssize_t total_len = iov_total_len(iov, count);
	ssize_t ret;

	do {
		ret = writev(sk, iov, count);
		if (ret > 0) {
			total_len -= ret;
			if (!total_len)
				break;

			while (ret) {
				if (ret >= iov->iov_len) {
					ret -= iov->iov_len;
					iov++;
					continue;
				}
				iov->iov_base += ret;
				iov->iov_len -= ret;
				ret = 0;
			}
		} else if (!ret)
			break;
		else if (errno == EAGAIN || errno == EINTR)
			continue;
		else
			break;
	} while (!exit_backend);

	if (!total_len)
		return 0;

	return 1;
}

static int fio_send_data(int sk, const void *p, unsigned int len)
{
	struct iovec iov = { .iov_base = (void *) p, .iov_len = len };

	assert(len <= sizeof(struct fio_net_cmd) + FIO_SERVER_MAX_FRAGMENT_PDU);

	return fio_sendv_data(sk, &iov, 1);
}

static int fio_recv_data(int sk, void *buf, unsigned int len, bool wait)
{
	int flags;
	char *p = buf;

	if (wait)
		flags = MSG_WAITALL;
	else
		flags = OS_MSG_DONTWAIT;

	do {
		int ret = recv(sk, p, len, flags);

		if (ret > 0) {
			len -= ret;
			if (!len)
				break;
			p += ret;
			continue;
		} else if (!ret)
			break;
		else if (errno == EAGAIN || errno == EINTR) {
			if (wait)
				continue;
			break;
		} else
			break;
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

	crc = fio_crc16(cmd, FIO_NET_CMD_CRC_SZ);
	if (crc != cmd->cmd_crc16) {
		log_err("fio: server bad crc on command (got %x, wanted %x)\n",
				cmd->cmd_crc16, crc);
		fprintf(f_err, "fio: server bad crc on command (got %x, wanted %x)\n",
				cmd->cmd_crc16, crc);
		return 1;
	}

	cmd->version	= le16_to_cpu(cmd->version);
	cmd->opcode	= le16_to_cpu(cmd->opcode);
	cmd->flags	= le32_to_cpu(cmd->flags);
	cmd->tag	= le64_to_cpu(cmd->tag);
	cmd->pdu_len	= le32_to_cpu(cmd->pdu_len);

	switch (cmd->version) {
	case FIO_SERVER_VER:
		break;
	default:
		log_err("fio: bad server cmd version %d\n", cmd->version);
		fprintf(f_err, "fio: client/server version mismatch (%d != %d)\n",
				cmd->version, FIO_SERVER_VER);
		return 1;
	}

	if (cmd->pdu_len > FIO_SERVER_MAX_FRAGMENT_PDU) {
		log_err("fio: command payload too large: %u\n", cmd->pdu_len);
		return 1;
	}

	return 0;
}

/*
 * Read (and defragment, if necessary) incoming commands
 */
struct fio_net_cmd *fio_net_recv_cmd(int sk, bool wait)
{
	struct fio_net_cmd cmd, *tmp, *cmdret = NULL;
	size_t cmd_size = 0, pdu_offset = 0;
	uint16_t crc;
	int ret, first = 1;
	void *pdu = NULL;

	do {
		ret = fio_recv_data(sk, &cmd, sizeof(cmd), wait);
		if (ret)
			break;

		/* We have a command, verify it and swap if need be */
		ret = verify_convert_cmd(&cmd);
		if (ret)
			break;

		if (first) {
			/* if this is text, add room for \0 at the end */
			cmd_size = sizeof(cmd) + cmd.pdu_len + 1;
			assert(!cmdret);
		} else
			cmd_size += cmd.pdu_len;

		if (cmd_size / 1024 > FIO_SERVER_MAX_CMD_MB * 1024) {
			log_err("fio: cmd+pdu too large (%llu)\n", (unsigned long long) cmd_size);
			ret = 1;
			break;
		}

		tmp = realloc(cmdret, cmd_size);
		if (!tmp) {
			log_err("fio: server failed allocating cmd\n");
			ret = 1;
			break;
		}
		cmdret = tmp;

		if (first)
			memcpy(cmdret, &cmd, sizeof(cmd));
		else if (cmdret->opcode != cmd.opcode) {
			log_err("fio: fragment opcode mismatch (%d != %d)\n",
					cmdret->opcode, cmd.opcode);
			ret = 1;
			break;
		}

		if (!cmd.pdu_len)
			break;

		/* There's payload, get it */
		pdu = (char *) cmdret->payload + pdu_offset;
		ret = fio_recv_data(sk, pdu, cmd.pdu_len, wait);
		if (ret)
			break;

		/* Verify payload crc */
		crc = fio_crc16(pdu, cmd.pdu_len);
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
	} else if (cmdret) {
		/* zero-terminate text input */
		if (cmdret->pdu_len) {
			if (cmdret->opcode == FIO_NET_CMD_TEXT) {
				struct cmd_text_pdu *__pdu = (struct cmd_text_pdu *) cmdret->payload;
				char *buf = (char *) __pdu->buf;

				buf[__pdu->buf_len] = '\0';
			} else if (cmdret->opcode == FIO_NET_CMD_JOB) {
				struct cmd_job_pdu *__pdu = (struct cmd_job_pdu *) cmdret->payload;
				char *buf = (char *) __pdu->buf;
				int len = le32_to_cpu(__pdu->buf_len);

				buf[len] = '\0';
			}
		}

		/* frag flag is internal */
		cmdret->flags &= ~FIO_NET_CMD_F_MORE;
	}

	return cmdret;
}

static void add_reply(uint64_t tag, struct flist_head *list)
{
	struct fio_net_cmd_reply *reply;

	reply = (struct fio_net_cmd_reply *) (uintptr_t) tag;
	flist_add_tail(&reply->list, list);
}

static uint64_t alloc_reply(uint64_t tag, uint16_t opcode)
{
	struct fio_net_cmd_reply *reply;

	reply = calloc(1, sizeof(*reply));
	INIT_FLIST_HEAD(&reply->list);
	fio_gettime(&reply->ts, NULL);
	reply->saved_tag = tag;
	reply->opcode = opcode;

	return (uintptr_t) reply;
}

static void free_reply(uint64_t tag)
{
	struct fio_net_cmd_reply *reply;

	reply = (struct fio_net_cmd_reply *) (uintptr_t) tag;
	free(reply);
}

static void fio_net_cmd_crc_pdu(struct fio_net_cmd *cmd, const void *pdu)
{
	uint32_t pdu_len;

	cmd->cmd_crc16 = __cpu_to_le16(fio_crc16(cmd, FIO_NET_CMD_CRC_SZ));

	pdu_len = le32_to_cpu(cmd->pdu_len);
	cmd->pdu_crc16 = __cpu_to_le16(fio_crc16(pdu, pdu_len));
}

static void fio_net_cmd_crc(struct fio_net_cmd *cmd)
{
	fio_net_cmd_crc_pdu(cmd, cmd->payload);
}

int fio_net_send_cmd(int fd, uint16_t opcode, const void *buf, off_t size,
		     uint64_t *tagptr, struct flist_head *list)
{
	struct fio_net_cmd *cmd = NULL;
	size_t this_len, cur_len = 0;
	uint64_t tag;
	int ret;

	if (list) {
		assert(tagptr);
		tag = *tagptr = alloc_reply(*tagptr, opcode);
	} else
		tag = tagptr ? *tagptr : 0;

	do {
		this_len = size;
		if (this_len > FIO_SERVER_MAX_FRAGMENT_PDU)
			this_len = FIO_SERVER_MAX_FRAGMENT_PDU;

		if (!cmd || cur_len < sizeof(*cmd) + this_len) {
			if (cmd)
				free(cmd);

			cur_len = sizeof(*cmd) + this_len;
			cmd = malloc(cur_len);
		}

		fio_init_net_cmd(cmd, opcode, buf, this_len, tag);

		if (this_len < size)
			cmd->flags = __cpu_to_le32(FIO_NET_CMD_F_MORE);

		fio_net_cmd_crc(cmd);

		ret = fio_send_data(fd, cmd, sizeof(*cmd) + this_len);
		size -= this_len;
		buf += this_len;
	} while (!ret && size);

	if (list) {
		if (ret)
			free_reply(tag);
		else
			add_reply(tag, list);
	}

	if (cmd)
		free(cmd);

	return ret;
}

static struct sk_entry *fio_net_prep_cmd(uint16_t opcode, void *buf,
					 size_t size, uint64_t *tagptr,
					 int flags)
{
	struct sk_entry *entry;

	entry = smalloc(sizeof(*entry));
	if (!entry)
		return NULL;

	INIT_FLIST_HEAD(&entry->next);
	entry->opcode = opcode;
	if (flags & SK_F_COPY) {
		entry->buf = smalloc(size);
		memcpy(entry->buf, buf, size);
	} else
		entry->buf = buf;

	entry->size = size;
	if (tagptr)
		entry->tag = *tagptr;
	else
		entry->tag = 0;
	entry->flags = flags;
	return entry;
}

static int handle_sk_entry(struct sk_out *sk_out, struct sk_entry *entry);

static void fio_net_queue_entry(struct sk_entry *entry)
{
	struct sk_out *sk_out = pthread_getspecific(sk_out_key);

	if (entry->flags & SK_F_INLINE)
		handle_sk_entry(sk_out, entry);
	else {
		sk_lock(sk_out);
		flist_add_tail(&entry->list, &sk_out->list);
		sk_unlock(sk_out);

		fio_sem_up(&sk_out->wait);
	}
}

static int fio_net_queue_cmd(uint16_t opcode, void *buf, off_t size,
			     uint64_t *tagptr, int flags)
{
	struct sk_entry *entry;

	entry = fio_net_prep_cmd(opcode, buf, size, tagptr, flags);
	if (entry) {
		fio_net_queue_entry(entry);
		return 0;
	}

	return 1;
}

static int fio_net_send_simple_stack_cmd(int sk, uint16_t opcode, uint64_t tag)
{
	struct fio_net_cmd cmd;

	fio_init_net_cmd(&cmd, opcode, NULL, 0, tag);
	fio_net_cmd_crc(&cmd);

	return fio_send_data(sk, &cmd, sizeof(cmd));
}

/*
 * If 'list' is non-NULL, then allocate and store the sent command for
 * later verification.
 */
int fio_net_send_simple_cmd(int sk, uint16_t opcode, uint64_t tag,
			    struct flist_head *list)
{
	int ret;

	if (list)
		tag = alloc_reply(tag, opcode);

	ret = fio_net_send_simple_stack_cmd(sk, opcode, tag);
	if (ret) {
		if (list)
			free_reply(tag);

		return ret;
	}

	if (list)
		add_reply(tag, list);

	return 0;
}

static int fio_net_queue_quit(void)
{
	dprint(FD_NET, "server: sending quit\n");

	return fio_net_queue_cmd(FIO_NET_CMD_QUIT, NULL, 0, NULL, SK_F_SIMPLE);
}

int fio_net_send_quit(int sk)
{
	dprint(FD_NET, "server: sending quit\n");

	return fio_net_send_simple_cmd(sk, FIO_NET_CMD_QUIT, 0, NULL);
}

static int fio_net_send_ack(struct fio_net_cmd *cmd, int error, int signal)
{
	struct cmd_end_pdu epdu;
	uint64_t tag = 0;

	if (cmd)
		tag = cmd->tag;

	epdu.error = __cpu_to_le32(error);
	epdu.signal = __cpu_to_le32(signal);
	return fio_net_queue_cmd(FIO_NET_CMD_STOP, &epdu, sizeof(epdu), &tag, SK_F_COPY);
}

static int fio_net_queue_stop(int error, int signal)
{
	dprint(FD_NET, "server: sending stop (%d, %d)\n", error, signal);
	return fio_net_send_ack(NULL, error, signal);
}

static void fio_server_add_fork_item(pid_t pid, struct flist_head *list)
{
	struct fio_fork_item *ffi;

	ffi = malloc(sizeof(*ffi));
	ffi->exitval = 0;
	ffi->signal = 0;
	ffi->exited = 0;
	ffi->pid = pid;
	flist_add_tail(&ffi->list, list);
}

static void fio_server_add_conn_pid(struct flist_head *conn_list, pid_t pid)
{
	dprint(FD_NET, "server: forked off connection job (pid=%u)\n", (int) pid);
	fio_server_add_fork_item(pid, conn_list);
}

static void fio_server_add_job_pid(struct flist_head *job_list, pid_t pid)
{
	dprint(FD_NET, "server: forked off job job (pid=%u)\n", (int) pid);
	fio_server_add_fork_item(pid, job_list);
}

static void fio_server_check_fork_item(struct fio_fork_item *ffi)
{
	int ret, status;

	ret = waitpid(ffi->pid, &status, WNOHANG);
	if (ret < 0) {
		if (errno == ECHILD) {
			log_err("fio: connection pid %u disappeared\n", (int) ffi->pid);
			ffi->exited = 1;
		} else
			log_err("fio: waitpid: %s\n", strerror(errno));
	} else if (ret == ffi->pid) {
		if (WIFSIGNALED(status)) {
			ffi->signal = WTERMSIG(status);
			ffi->exited = 1;
		}
		if (WIFEXITED(status)) {
			if (WEXITSTATUS(status))
				ffi->exitval = WEXITSTATUS(status);
			ffi->exited = 1;
		}
	}
}

static void fio_server_fork_item_done(struct fio_fork_item *ffi, bool stop)
{
	dprint(FD_NET, "pid %u exited, sig=%u, exitval=%d\n", (int) ffi->pid, ffi->signal, ffi->exitval);

	/*
	 * Fold STOP and QUIT...
	 */
	if (stop) {
		fio_net_queue_stop(ffi->exitval, ffi->signal);
		fio_net_queue_quit();
	}

	flist_del(&ffi->list);
	free(ffi);
}

static void fio_server_check_fork_items(struct flist_head *list, bool stop)
{
	struct flist_head *entry, *tmp;
	struct fio_fork_item *ffi;

	flist_for_each_safe(entry, tmp, list) {
		ffi = flist_entry(entry, struct fio_fork_item, list);

		fio_server_check_fork_item(ffi);

		if (ffi->exited)
			fio_server_fork_item_done(ffi, stop);
	}
}

static void fio_server_check_jobs(struct flist_head *job_list)
{
	fio_server_check_fork_items(job_list, true);
}

static void fio_server_check_conns(struct flist_head *conn_list)
{
	fio_server_check_fork_items(conn_list, false);
}

static int handle_load_file_cmd(struct fio_net_cmd *cmd)
{
	struct cmd_load_file_pdu *pdu = (struct cmd_load_file_pdu *) cmd->payload;
	void *file_name = pdu->file;
	struct cmd_start_pdu spdu;

	dprint(FD_NET, "server: loading local file %s\n", (char *) file_name);

	pdu->name_len = le16_to_cpu(pdu->name_len);
	pdu->client_type = le16_to_cpu(pdu->client_type);

	if (parse_jobs_ini(file_name, 0, 0, pdu->client_type)) {
		fio_net_queue_quit();
		return -1;
	}

	spdu.jobs = cpu_to_le32(thread_number);
	spdu.stat_outputs = cpu_to_le32(stat_number);
	fio_net_queue_cmd(FIO_NET_CMD_START, &spdu, sizeof(spdu), NULL, SK_F_COPY);
	return 0;
}

static int handle_run_cmd(struct sk_out *sk_out, struct flist_head *job_list,
			  struct fio_net_cmd *cmd)
{
	pid_t pid;
	int ret;

	sk_out_assign(sk_out);

	fio_time_init();
	set_genesis_time();

	pid = fork();
	if (pid) {
		fio_server_add_job_pid(job_list, pid);
		return 0;
	}

	ret = fio_backend(sk_out);
	free_threads_shm();
	sk_out_drop();
	_exit(ret);
}

static int handle_job_cmd(struct fio_net_cmd *cmd)
{
	struct cmd_job_pdu *pdu = (struct cmd_job_pdu *) cmd->payload;
	void *buf = pdu->buf;
	struct cmd_start_pdu spdu;

	pdu->buf_len = le32_to_cpu(pdu->buf_len);
	pdu->client_type = le32_to_cpu(pdu->client_type);

	if (parse_jobs_ini(buf, 1, 0, pdu->client_type)) {
		fio_net_queue_quit();
		return -1;
	}

	spdu.jobs = cpu_to_le32(thread_number);
	spdu.stat_outputs = cpu_to_le32(stat_number);

	fio_net_queue_cmd(FIO_NET_CMD_START, &spdu, sizeof(spdu), NULL, SK_F_COPY);
	return 0;
}

static int handle_jobline_cmd(struct fio_net_cmd *cmd)
{
	void *pdu = cmd->payload;
	struct cmd_single_line_pdu *cslp;
	struct cmd_line_pdu *clp;
	unsigned long offset;
	struct cmd_start_pdu spdu;
	char **argv;
	int i;

	clp = pdu;
	clp->lines = le16_to_cpu(clp->lines);
	clp->client_type = le16_to_cpu(clp->client_type);
	argv = malloc(clp->lines * sizeof(char *));
	offset = sizeof(*clp);

	dprint(FD_NET, "server: %d command line args\n", clp->lines);

	for (i = 0; i < clp->lines; i++) {
		cslp = pdu + offset;
		argv[i] = (char *) cslp->text;

		offset += sizeof(*cslp) + le16_to_cpu(cslp->len);
		dprint(FD_NET, "server: %d: %s\n", i, argv[i]);
	}

	if (parse_cmd_line(clp->lines, argv, clp->client_type)) {
		fio_net_queue_quit();
		free(argv);
		return -1;
	}

	free(argv);

	spdu.jobs = cpu_to_le32(thread_number);
	spdu.stat_outputs = cpu_to_le32(stat_number);

	fio_net_queue_cmd(FIO_NET_CMD_START, &spdu, sizeof(spdu), NULL, SK_F_COPY);
	return 0;
}

static int handle_probe_cmd(struct fio_net_cmd *cmd)
{
	struct cmd_client_probe_pdu *pdu = (struct cmd_client_probe_pdu *) cmd->payload;
	uint64_t tag = cmd->tag;
	struct cmd_probe_reply_pdu probe = {
#ifdef CONFIG_BIG_ENDIAN
		.bigendian	= 1,
#endif
		.os		= FIO_OS,
		.arch		= FIO_ARCH,
		.bpp		= sizeof(void *),
		.cpus		= __cpu_to_le32(cpus_online()),
	};

	dprint(FD_NET, "server: sending probe reply\n");

	strcpy(me, (char *) pdu->server);

	gethostname((char *) probe.hostname, sizeof(probe.hostname));
	snprintf((char *) probe.fio_version, sizeof(probe.fio_version), "%s",
		 fio_version_string);

	/*
	 * If the client supports compression and we do too, then enable it
	 */
	if (has_zlib && le64_to_cpu(pdu->flags) & FIO_PROBE_FLAG_ZLIB) {
		probe.flags = __cpu_to_le64(FIO_PROBE_FLAG_ZLIB);
		use_zlib = 1;
	} else {
		probe.flags = 0;
		use_zlib = 0;
	}

	return fio_net_queue_cmd(FIO_NET_CMD_PROBE, &probe, sizeof(probe), &tag, SK_F_COPY);
}

static int handle_send_eta_cmd(struct fio_net_cmd *cmd)
{
	struct jobs_eta *je;
	uint64_t tag = cmd->tag;
	size_t size;
	int i;

	dprint(FD_NET, "server sending status\n");

	/*
	 * Fake ETA return if we don't have a local one, otherwise the client
	 * will end up timing out waiting for a response to the ETA request
	 */
	je = get_jobs_eta(true, &size);
	if (!je) {
		size = sizeof(*je);
		je = calloc(1, size);
	} else {
		je->nr_running		= cpu_to_le32(je->nr_running);
		je->nr_ramp		= cpu_to_le32(je->nr_ramp);
		je->nr_pending		= cpu_to_le32(je->nr_pending);
		je->nr_setting_up	= cpu_to_le32(je->nr_setting_up);
		je->files_open		= cpu_to_le32(je->files_open);

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			je->m_rate[i]	= cpu_to_le64(je->m_rate[i]);
			je->t_rate[i]	= cpu_to_le64(je->t_rate[i]);
			je->m_iops[i]	= cpu_to_le32(je->m_iops[i]);
			je->t_iops[i]	= cpu_to_le32(je->t_iops[i]);
			je->rate[i]	= cpu_to_le64(je->rate[i]);
			je->iops[i]	= cpu_to_le32(je->iops[i]);
		}

		je->elapsed_sec		= cpu_to_le64(je->elapsed_sec);
		je->eta_sec		= cpu_to_le64(je->eta_sec);
		je->nr_threads		= cpu_to_le32(je->nr_threads);
		je->is_pow2		= cpu_to_le32(je->is_pow2);
		je->unit_base		= cpu_to_le32(je->unit_base);
	}

	fio_net_queue_cmd(FIO_NET_CMD_ETA, je, size, &tag, SK_F_FREE);
	return 0;
}

static int send_update_job_reply(uint64_t __tag, int error)
{
	uint64_t tag = __tag;
	uint32_t pdu_error;

	pdu_error = __cpu_to_le32(error);
	return fio_net_queue_cmd(FIO_NET_CMD_UPDATE_JOB, &pdu_error, sizeof(pdu_error), &tag, SK_F_COPY);
}

static int handle_update_job_cmd(struct fio_net_cmd *cmd)
{
	struct cmd_add_job_pdu *pdu = (struct cmd_add_job_pdu *) cmd->payload;
	struct thread_data *td;
	uint32_t tnumber;

	tnumber = le32_to_cpu(pdu->thread_number);

	dprint(FD_NET, "server: updating options for job %u\n", tnumber);

	if (!tnumber || tnumber > thread_number) {
		send_update_job_reply(cmd->tag, ENODEV);
		return 0;
	}

	td = &threads[tnumber - 1];
	convert_thread_options_to_cpu(&td->o, &pdu->top);
	send_update_job_reply(cmd->tag, 0);
	return 0;
}

static int handle_trigger_cmd(struct fio_net_cmd *cmd, struct flist_head *job_list)
{
	struct cmd_vtrigger_pdu *pdu = (struct cmd_vtrigger_pdu *) cmd->payload;
	char *buf = (char *) pdu->cmd;
	struct all_io_list *rep;
	size_t sz;

	pdu->len = le16_to_cpu(pdu->len);
	buf[pdu->len] = '\0';

	rep = get_all_io_list(IO_LIST_ALL, &sz);
	if (!rep) {
		struct all_io_list state;

		state.threads = cpu_to_le64((uint64_t) 0);
		fio_net_queue_cmd(FIO_NET_CMD_VTRIGGER, &state, sizeof(state), NULL, SK_F_COPY | SK_F_INLINE);
	} else
		fio_net_queue_cmd(FIO_NET_CMD_VTRIGGER, rep, sz, NULL, SK_F_FREE | SK_F_INLINE);

	fio_terminate_threads(TERMINATE_ALL, TERMINATE_ALL);
	fio_server_check_jobs(job_list);
	exec_trigger(buf);
	return 0;
}

static int handle_command(struct sk_out *sk_out, struct flist_head *job_list,
			  struct fio_net_cmd *cmd)
{
	int ret;

	dprint(FD_NET, "server: got op [%s], pdu=%u, tag=%llx\n",
			fio_server_op(cmd->opcode), cmd->pdu_len,
			(unsigned long long) cmd->tag);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
		fio_terminate_threads(TERMINATE_ALL, TERMINATE_ALL);
		ret = 0;
		break;
	case FIO_NET_CMD_EXIT:
		exit_backend = true;
		return -1;
	case FIO_NET_CMD_LOAD_FILE:
		ret = handle_load_file_cmd(cmd);
		break;
	case FIO_NET_CMD_JOB:
		ret = handle_job_cmd(cmd);
		break;
	case FIO_NET_CMD_JOBLINE:
		ret = handle_jobline_cmd(cmd);
		break;
	case FIO_NET_CMD_PROBE:
		ret = handle_probe_cmd(cmd);
		break;
	case FIO_NET_CMD_SEND_ETA:
		ret = handle_send_eta_cmd(cmd);
		break;
	case FIO_NET_CMD_RUN:
		ret = handle_run_cmd(sk_out, job_list, cmd);
		break;
	case FIO_NET_CMD_UPDATE_JOB:
		ret = handle_update_job_cmd(cmd);
		break;
	case FIO_NET_CMD_VTRIGGER:
		ret = handle_trigger_cmd(cmd, job_list);
		break;
	case FIO_NET_CMD_SENDFILE: {
		struct cmd_sendfile_reply *in;
		struct cmd_reply *rep;

		rep = (struct cmd_reply *) (uintptr_t) cmd->tag;

		in = (struct cmd_sendfile_reply *) cmd->payload;
		in->size = le32_to_cpu(in->size);
		in->error = le32_to_cpu(in->error);
		if (in->error) {
			ret = 1;
			rep->error = in->error;
		} else {
			ret = 0;
			rep->data = smalloc(in->size);
			if (!rep->data) {
				ret = 1;
				rep->error = ENOMEM;
			} else {
				rep->size = in->size;
				memcpy(rep->data, in->data, in->size);
			}
		}
		fio_sem_up(&rep->lock);
		break;
		}
	default:
		log_err("fio: unknown opcode: %s\n", fio_server_op(cmd->opcode));
		ret = 1;
	}

	return ret;
}

/*
 * Send a command with a separate PDU, not inlined in the command
 */
static int fio_send_cmd_ext_pdu(int sk, uint16_t opcode, const void *buf,
				off_t size, uint64_t tag, uint32_t flags)
{
	struct fio_net_cmd cmd;
	struct iovec iov[2];
	size_t this_len;
	int ret;

	iov[0].iov_base = (void *) &cmd;
	iov[0].iov_len = sizeof(cmd);

	do {
		uint32_t this_flags = flags;

		this_len = size;
		if (this_len > FIO_SERVER_MAX_FRAGMENT_PDU)
			this_len = FIO_SERVER_MAX_FRAGMENT_PDU;

		if (this_len < size)
			this_flags |= FIO_NET_CMD_F_MORE;

		__fio_init_net_cmd(&cmd, opcode, this_len, tag);
		cmd.flags = __cpu_to_le32(this_flags);
		fio_net_cmd_crc_pdu(&cmd, buf);

		iov[1].iov_base = (void *) buf;
		iov[1].iov_len = this_len;

		ret = fio_sendv_data(sk, iov, 2);
		size -= this_len;
		buf += this_len;
	} while (!ret && size);

	return ret;
}

static void finish_entry(struct sk_entry *entry)
{
	if (entry->flags & SK_F_FREE)
		free(entry->buf);
	else if (entry->flags & SK_F_COPY)
		sfree(entry->buf);

	sfree(entry);
}

static void entry_set_flags(struct sk_entry *entry, struct flist_head *list,
			    unsigned int *flags)
{
	if (!flist_empty(list))
		*flags = FIO_NET_CMD_F_MORE;
	else
		*flags = 0;
}

static int send_vec_entry(struct sk_out *sk_out, struct sk_entry *first)
{
	unsigned int flags;
	int ret;

	entry_set_flags(first, &first->next, &flags);

	ret = fio_send_cmd_ext_pdu(sk_out->sk, first->opcode, first->buf,
					first->size, first->tag, flags);

	while (!flist_empty(&first->next)) {
		struct sk_entry *next;

		next = flist_first_entry(&first->next, struct sk_entry, list);
		flist_del_init(&next->list);

		entry_set_flags(next, &first->next, &flags);

		ret += fio_send_cmd_ext_pdu(sk_out->sk, next->opcode, next->buf,
						next->size, next->tag, flags);
		finish_entry(next);
	}

	return ret;
}

static int handle_sk_entry(struct sk_out *sk_out, struct sk_entry *entry)
{
	int ret;

	fio_sem_down(&sk_out->xmit);

	if (entry->flags & SK_F_VEC)
		ret = send_vec_entry(sk_out, entry);
	else if (entry->flags & SK_F_SIMPLE) {
		ret = fio_net_send_simple_cmd(sk_out->sk, entry->opcode,
						entry->tag, NULL);
	} else {
		ret = fio_net_send_cmd(sk_out->sk, entry->opcode, entry->buf,
					entry->size, &entry->tag, NULL);
	}

	fio_sem_up(&sk_out->xmit);

	if (ret)
		log_err("fio: failed handling cmd %s\n", fio_server_op(entry->opcode));

	finish_entry(entry);
	return ret;
}

static int handle_xmits(struct sk_out *sk_out)
{
	struct sk_entry *entry;
	FLIST_HEAD(list);
	int ret = 0;

	sk_lock(sk_out);
	if (flist_empty(&sk_out->list)) {
		sk_unlock(sk_out);
		return 0;
	}

	flist_splice_init(&sk_out->list, &list);
	sk_unlock(sk_out);

	while (!flist_empty(&list)) {
		entry = flist_entry(list.next, struct sk_entry, list);
		flist_del(&entry->list);
		ret += handle_sk_entry(sk_out, entry);
	}

	return ret;
}

static int handle_connection(struct sk_out *sk_out)
{
	struct fio_net_cmd *cmd = NULL;
	FLIST_HEAD(job_list);
	int ret = 0;

	reset_fio_state();

	/* read forever */
	while (!exit_backend) {
		struct pollfd pfd = {
			.fd	= sk_out->sk,
			.events	= POLLIN,
		};

		do {
			int timeout = 1000;

			if (!flist_empty(&job_list))
				timeout = 100;

			handle_xmits(sk_out);

			ret = poll(&pfd, 1, 0);
			if (ret < 0) {
				if (errno == EINTR)
					break;
				log_err("fio: poll: %s\n", strerror(errno));
				break;
			} else if (!ret) {
				fio_server_check_jobs(&job_list);
				fio_sem_down_timeout(&sk_out->wait, timeout);
				continue;
			}

			if (pfd.revents & POLLIN)
				break;
			if (pfd.revents & (POLLERR|POLLHUP)) {
				ret = 1;
				break;
			}
		} while (!exit_backend);

		fio_server_check_jobs(&job_list);

		if (ret < 0)
			break;

		cmd = fio_net_recv_cmd(sk_out->sk, true);
		if (!cmd) {
			ret = -1;
			break;
		}

		ret = handle_command(sk_out, &job_list, cmd);
		if (ret)
			break;

		free(cmd);
		cmd = NULL;
	}

	if (cmd)
		free(cmd);

	handle_xmits(sk_out);

	close(sk_out->sk);
	sk_out->sk = -1;
	__sk_out_drop(sk_out);
	_exit(ret);
}

/* get the address on this host bound by the input socket,
 * whether it is ipv6 or ipv4 */

static int get_my_addr_str(int sk)
{
	struct sockaddr_in6 myaddr6 = { 0, };
	struct sockaddr_in myaddr4 = { 0, };
	struct sockaddr *sockaddr_p;
	char *net_addr;
	socklen_t len;
	int ret;

	if (use_ipv6) {
		len = sizeof(myaddr6);
		sockaddr_p = (struct sockaddr * )&myaddr6;
		net_addr = (char * )&myaddr6.sin6_addr;
	} else {
		len = sizeof(myaddr4);
		sockaddr_p = (struct sockaddr * )&myaddr4;
		net_addr = (char * )&myaddr4.sin_addr;
	}

	ret = getsockname(sk, sockaddr_p, &len);
	if (ret) {
		log_err("fio: getsockname: %s\n", strerror(errno));
		return -1;
	}

	if (!inet_ntop(use_ipv6?AF_INET6:AF_INET, net_addr, client_sockaddr_str, INET6_ADDRSTRLEN - 1)) {
		log_err("inet_ntop: failed to convert addr to string\n");
		return -1;
	}

	dprint(FD_NET, "fio server bound to addr %s\n", client_sockaddr_str);
	return 0;
}

static int accept_loop(int listen_sk)
{
	struct sockaddr_in addr;
	struct sockaddr_in6 addr6;
	socklen_t len = use_ipv6 ? sizeof(addr6) : sizeof(addr);
	struct pollfd pfd;
	int ret = 0, sk, exitval = 0;
	FLIST_HEAD(conn_list);

	dprint(FD_NET, "server enter accept loop\n");

	fio_set_fd_nonblocking(listen_sk, "server");

	while (!exit_backend) {
		struct sk_out *sk_out;
		const char *from;
		char buf[64];
		pid_t pid;

		pfd.fd = listen_sk;
		pfd.events = POLLIN;
		do {
			int timeout = 1000;

			if (!flist_empty(&conn_list))
				timeout = 100;

			ret = poll(&pfd, 1, timeout);
			if (ret < 0) {
				if (errno == EINTR)
					break;
				log_err("fio: poll: %s\n", strerror(errno));
				break;
			} else if (!ret) {
				fio_server_check_conns(&conn_list);
				continue;
			}

			if (pfd.revents & POLLIN)
				break;
		} while (!exit_backend);

		fio_server_check_conns(&conn_list);

		if (exit_backend || ret < 0)
			break;

		if (use_ipv6)
			sk = accept(listen_sk, (struct sockaddr *) &addr6, &len);
		else
			sk = accept(listen_sk, (struct sockaddr *) &addr, &len);

		if (sk < 0) {
			log_err("fio: accept: %s\n", strerror(errno));
			return -1;
		}

		if (use_ipv6)
			from = inet_ntop(AF_INET6, (struct sockaddr *) &addr6.sin6_addr, buf, sizeof(buf));
		else
			from = inet_ntop(AF_INET, (struct sockaddr *) &addr.sin_addr, buf, sizeof(buf));

		dprint(FD_NET, "server: connect from %s\n", from);

		sk_out = scalloc(1, sizeof(*sk_out));
		if (!sk_out) {
			close(sk);
			return -1;
		}

		sk_out->sk = sk;
		INIT_FLIST_HEAD(&sk_out->list);
		__fio_sem_init(&sk_out->lock, FIO_SEM_UNLOCKED);
		__fio_sem_init(&sk_out->wait, FIO_SEM_LOCKED);
		__fio_sem_init(&sk_out->xmit, FIO_SEM_UNLOCKED);

		pid = fork();
		if (pid) {
			close(sk);
			fio_server_add_conn_pid(&conn_list, pid);
			continue;
		}

		/* if error, it's already logged, non-fatal */
		get_my_addr_str(sk);

		/*
		 * Assign sk_out here, it'll be dropped in handle_connection()
		 * since that function calls _exit() when done
		 */
		sk_out_assign(sk_out);
		handle_connection(sk_out);
	}

	return exitval;
}

int fio_server_text_output(int level, const char *buf, size_t len)
{
	struct sk_out *sk_out = pthread_getspecific(sk_out_key);
	struct cmd_text_pdu *pdu;
	unsigned int tlen;
	struct timeval tv;

	if (!sk_out || sk_out->sk == -1)
		return -1;

	tlen = sizeof(*pdu) + len;
	pdu = malloc(tlen);

	pdu->level	= __cpu_to_le32(level);
	pdu->buf_len	= __cpu_to_le32(len);

	gettimeofday(&tv, NULL);
	pdu->log_sec	= __cpu_to_le64(tv.tv_sec);
	pdu->log_usec	= __cpu_to_le64(tv.tv_usec);

	memcpy(pdu->buf, buf, len);

	fio_net_queue_cmd(FIO_NET_CMD_TEXT, pdu, tlen, NULL, SK_F_COPY);
	free(pdu);
	return len;
}

static void convert_io_stat(struct io_stat *dst, struct io_stat *src)
{
	dst->max_val	= cpu_to_le64(src->max_val);
	dst->min_val	= cpu_to_le64(src->min_val);
	dst->samples	= cpu_to_le64(src->samples);

	/*
	 * Encode to IEEE 754 for network transfer
	 */
	dst->mean.u.i	= cpu_to_le64(fio_double_to_uint64(src->mean.u.f));
	dst->S.u.i	= cpu_to_le64(fio_double_to_uint64(src->S.u.f));
}

static void convert_gs(struct group_run_stats *dst, struct group_run_stats *src)
{
	int i;

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		dst->max_run[i]		= cpu_to_le64(src->max_run[i]);
		dst->min_run[i]		= cpu_to_le64(src->min_run[i]);
		dst->max_bw[i]		= cpu_to_le64(src->max_bw[i]);
		dst->min_bw[i]		= cpu_to_le64(src->min_bw[i]);
		dst->iobytes[i]		= cpu_to_le64(src->iobytes[i]);
		dst->agg[i]		= cpu_to_le64(src->agg[i]);
	}

	dst->kb_base	= cpu_to_le32(src->kb_base);
	dst->unit_base	= cpu_to_le32(src->unit_base);
	dst->groupid	= cpu_to_le32(src->groupid);
	dst->unified_rw_rep	= cpu_to_le32(src->unified_rw_rep);
	dst->sig_figs	= cpu_to_le32(src->sig_figs);
}

/*
 * Send a CMD_TS, which packs struct thread_stat and group_run_stats
 * into a single payload.
 */
void fio_server_send_ts(struct thread_stat *ts, struct group_run_stats *rs)
{
	struct cmd_ts_pdu p;
	int i, j, k;
	void *ss_buf;
	uint64_t *ss_iops, *ss_bw;

	dprint(FD_NET, "server sending end stats\n");

	memset(&p, 0, sizeof(p));

	snprintf(p.ts.name, sizeof(p.ts.name), "%s", ts->name);
	snprintf(p.ts.verror, sizeof(p.ts.verror), "%s", ts->verror);
	snprintf(p.ts.description, sizeof(p.ts.description), "%s",
		 ts->description);

	p.ts.error		= cpu_to_le32(ts->error);
	p.ts.thread_number	= cpu_to_le32(ts->thread_number);
	p.ts.groupid		= cpu_to_le32(ts->groupid);
	p.ts.pid		= cpu_to_le32(ts->pid);
	p.ts.members		= cpu_to_le32(ts->members);
	p.ts.unified_rw_rep	= cpu_to_le32(ts->unified_rw_rep);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		convert_io_stat(&p.ts.clat_stat[i], &ts->clat_stat[i]);
		convert_io_stat(&p.ts.slat_stat[i], &ts->slat_stat[i]);
		convert_io_stat(&p.ts.lat_stat[i], &ts->lat_stat[i]);
		convert_io_stat(&p.ts.bw_stat[i], &ts->bw_stat[i]);
		convert_io_stat(&p.ts.iops_stat[i], &ts->iops_stat[i]);
	}
	convert_io_stat(&p.ts.sync_stat, &ts->sync_stat);

	p.ts.usr_time		= cpu_to_le64(ts->usr_time);
	p.ts.sys_time		= cpu_to_le64(ts->sys_time);
	p.ts.ctx		= cpu_to_le64(ts->ctx);
	p.ts.minf		= cpu_to_le64(ts->minf);
	p.ts.majf		= cpu_to_le64(ts->majf);
	p.ts.clat_percentiles	= cpu_to_le32(ts->clat_percentiles);
	p.ts.lat_percentiles	= cpu_to_le32(ts->lat_percentiles);
	p.ts.slat_percentiles	= cpu_to_le32(ts->slat_percentiles);
	p.ts.percentile_precision = cpu_to_le64(ts->percentile_precision);

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		fio_fp64_t *src = &ts->percentile_list[i];
		fio_fp64_t *dst = &p.ts.percentile_list[i];

		dst->u.i = cpu_to_le64(fio_double_to_uint64(src->u.f));
	}

	for (i = 0; i < FIO_IO_U_MAP_NR; i++) {
		p.ts.io_u_map[i]	= cpu_to_le64(ts->io_u_map[i]);
		p.ts.io_u_submit[i]	= cpu_to_le64(ts->io_u_submit[i]);
		p.ts.io_u_complete[i]	= cpu_to_le64(ts->io_u_complete[i]);
	}

	for (i = 0; i < FIO_IO_U_LAT_N_NR; i++)
		p.ts.io_u_lat_n[i]	= cpu_to_le64(ts->io_u_lat_n[i]);
	for (i = 0; i < FIO_IO_U_LAT_U_NR; i++)
		p.ts.io_u_lat_u[i]	= cpu_to_le64(ts->io_u_lat_u[i]);
	for (i = 0; i < FIO_IO_U_LAT_M_NR; i++)
		p.ts.io_u_lat_m[i]	= cpu_to_le64(ts->io_u_lat_m[i]);

	for (i = 0; i < FIO_LAT_CNT; i++)
		for (j = 0; j < DDIR_RWDIR_CNT; j++)
			for (k = 0; k < FIO_IO_U_PLAT_NR; k++)
				p.ts.io_u_plat[i][j][k] = cpu_to_le64(ts->io_u_plat[i][j][k]);

	for (j = 0; j < FIO_IO_U_PLAT_NR; j++)
		p.ts.io_u_sync_plat[j] = cpu_to_le64(ts->io_u_sync_plat[j]);

	for (i = 0; i < DDIR_RWDIR_SYNC_CNT; i++)
		p.ts.total_io_u[i]	= cpu_to_le64(ts->total_io_u[i]);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		p.ts.short_io_u[i]	= cpu_to_le64(ts->short_io_u[i]);
		p.ts.drop_io_u[i]	= cpu_to_le64(ts->drop_io_u[i]);
	}

	p.ts.total_submit	= cpu_to_le64(ts->total_submit);
	p.ts.total_complete	= cpu_to_le64(ts->total_complete);
	p.ts.nr_zone_resets	= cpu_to_le64(ts->nr_zone_resets);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		p.ts.io_bytes[i]	= cpu_to_le64(ts->io_bytes[i]);
		p.ts.runtime[i]		= cpu_to_le64(ts->runtime[i]);
	}

	p.ts.total_run_time	= cpu_to_le64(ts->total_run_time);
	p.ts.continue_on_error	= cpu_to_le16(ts->continue_on_error);
	p.ts.total_err_count	= cpu_to_le64(ts->total_err_count);
	p.ts.first_error	= cpu_to_le32(ts->first_error);
	p.ts.kb_base		= cpu_to_le32(ts->kb_base);
	p.ts.unit_base		= cpu_to_le32(ts->unit_base);

	p.ts.latency_depth	= cpu_to_le32(ts->latency_depth);
	p.ts.latency_target	= cpu_to_le64(ts->latency_target);
	p.ts.latency_window	= cpu_to_le64(ts->latency_window);
	p.ts.latency_percentile.u.i = cpu_to_le64(fio_double_to_uint64(ts->latency_percentile.u.f));

	p.ts.sig_figs		= cpu_to_le32(ts->sig_figs);

	p.ts.nr_block_infos	= cpu_to_le64(ts->nr_block_infos);
	for (i = 0; i < p.ts.nr_block_infos; i++)
		p.ts.block_infos[i] = cpu_to_le32(ts->block_infos[i]);

	p.ts.ss_dur		= cpu_to_le64(ts->ss_dur);
	p.ts.ss_state		= cpu_to_le32(ts->ss_state);
	p.ts.ss_head		= cpu_to_le32(ts->ss_head);
	p.ts.ss_limit.u.i	= cpu_to_le64(fio_double_to_uint64(ts->ss_limit.u.f));
	p.ts.ss_slope.u.i	= cpu_to_le64(fio_double_to_uint64(ts->ss_slope.u.f));
	p.ts.ss_deviation.u.i	= cpu_to_le64(fio_double_to_uint64(ts->ss_deviation.u.f));
	p.ts.ss_criterion.u.i	= cpu_to_le64(fio_double_to_uint64(ts->ss_criterion.u.f));

	p.ts.cachehit		= cpu_to_le64(ts->cachehit);
	p.ts.cachemiss		= cpu_to_le64(ts->cachemiss);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		for (j = 0; j < FIO_IO_U_PLAT_NR; j++) {
			p.ts.io_u_plat_high_prio[i][j] = cpu_to_le64(ts->io_u_plat_high_prio[i][j]);
			p.ts.io_u_plat_low_prio[i][j] = cpu_to_le64(ts->io_u_plat_low_prio[i][j]);
		}
		convert_io_stat(&p.ts.clat_high_prio_stat[i], &ts->clat_high_prio_stat[i]);
		convert_io_stat(&p.ts.clat_low_prio_stat[i], &ts->clat_low_prio_stat[i]);
	}

	convert_gs(&p.rs, rs);

	dprint(FD_NET, "ts->ss_state = %d\n", ts->ss_state);
	if (ts->ss_state & FIO_SS_DATA) {
		dprint(FD_NET, "server sending steadystate ring buffers\n");

		ss_buf = malloc(sizeof(p) + 2*ts->ss_dur*sizeof(uint64_t));

		memcpy(ss_buf, &p, sizeof(p));

		ss_iops = (uint64_t *) ((struct cmd_ts_pdu *)ss_buf + 1);
		ss_bw = ss_iops + (int) ts->ss_dur;
		for (i = 0; i < ts->ss_dur; i++) {
			ss_iops[i] = cpu_to_le64(ts->ss_iops_data[i]);
			ss_bw[i] = cpu_to_le64(ts->ss_bw_data[i]);
		}

		fio_net_queue_cmd(FIO_NET_CMD_TS, ss_buf, sizeof(p) + 2*ts->ss_dur*sizeof(uint64_t), NULL, SK_F_COPY);

		free(ss_buf);
	}
	else
		fio_net_queue_cmd(FIO_NET_CMD_TS, &p, sizeof(p), NULL, SK_F_COPY);
}

void fio_server_send_gs(struct group_run_stats *rs)
{
	struct group_run_stats gs;

	dprint(FD_NET, "server sending group run stats\n");

	convert_gs(&gs, rs);
	fio_net_queue_cmd(FIO_NET_CMD_GS, &gs, sizeof(gs), NULL, SK_F_COPY);
}

void fio_server_send_job_options(struct flist_head *opt_list,
				 unsigned int gid)
{
	struct cmd_job_option pdu;
	struct flist_head *entry;

	if (flist_empty(opt_list))
		return;

	flist_for_each(entry, opt_list) {
		struct print_option *p;
		size_t len;

		p = flist_entry(entry, struct print_option, list);
		memset(&pdu, 0, sizeof(pdu));

		if (gid == -1U) {
			pdu.global = __cpu_to_le16(1);
			pdu.groupid = 0;
		} else {
			pdu.global = 0;
			pdu.groupid = cpu_to_le32(gid);
		}
		len = strlen(p->name);
		if (len >= sizeof(pdu.name)) {
			len = sizeof(pdu.name) - 1;
			pdu.truncated = __cpu_to_le16(1);
		}
		memcpy(pdu.name, p->name, len);
		if (p->value) {
			len = strlen(p->value);
			if (len >= sizeof(pdu.value)) {
				len = sizeof(pdu.value) - 1;
				pdu.truncated = __cpu_to_le16(1);
			}
			memcpy(pdu.value, p->value, len);
		}
		fio_net_queue_cmd(FIO_NET_CMD_JOB_OPT, &pdu, sizeof(pdu), NULL, SK_F_COPY);
	}
}

static void convert_agg(struct disk_util_agg *dst, struct disk_util_agg *src)
{
	int i;

	for (i = 0; i < 2; i++) {
		dst->ios[i]	= cpu_to_le64(src->ios[i]);
		dst->merges[i]	= cpu_to_le64(src->merges[i]);
		dst->sectors[i]	= cpu_to_le64(src->sectors[i]);
		dst->ticks[i]	= cpu_to_le64(src->ticks[i]);
	}

	dst->io_ticks		= cpu_to_le64(src->io_ticks);
	dst->time_in_queue	= cpu_to_le64(src->time_in_queue);
	dst->slavecount		= cpu_to_le32(src->slavecount);
	dst->max_util.u.i	= cpu_to_le64(fio_double_to_uint64(src->max_util.u.f));
}

static void convert_dus(struct disk_util_stat *dst, struct disk_util_stat *src)
{
	int i;

	snprintf((char *) dst->name, sizeof(dst->name), "%s", src->name);

	for (i = 0; i < 2; i++) {
		dst->s.ios[i]		= cpu_to_le64(src->s.ios[i]);
		dst->s.merges[i]	= cpu_to_le64(src->s.merges[i]);
		dst->s.sectors[i]	= cpu_to_le64(src->s.sectors[i]);
		dst->s.ticks[i]		= cpu_to_le64(src->s.ticks[i]);
	}

	dst->s.io_ticks		= cpu_to_le64(src->s.io_ticks);
	dst->s.time_in_queue	= cpu_to_le64(src->s.time_in_queue);
	dst->s.msec		= cpu_to_le64(src->s.msec);
}

void fio_server_send_du(void)
{
	struct disk_util *du;
	struct flist_head *entry;
	struct cmd_du_pdu pdu;

	dprint(FD_NET, "server: sending disk_util %d\n", !flist_empty(&disk_list));

	memset(&pdu, 0, sizeof(pdu));

	flist_for_each(entry, &disk_list) {
		du = flist_entry(entry, struct disk_util, list);

		convert_dus(&pdu.dus, &du->dus);
		convert_agg(&pdu.agg, &du->agg);

		fio_net_queue_cmd(FIO_NET_CMD_DU, &pdu, sizeof(pdu), NULL, SK_F_COPY);
	}
}

#ifdef CONFIG_ZLIB

static inline void __fio_net_prep_tail(z_stream *stream, void *out_pdu,
					struct sk_entry **last_entry,
					struct sk_entry *first)
{
	unsigned int this_len = FIO_SERVER_MAX_FRAGMENT_PDU - stream->avail_out;

	*last_entry = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, out_pdu, this_len,
				 NULL, SK_F_VEC | SK_F_INLINE | SK_F_FREE);
	if (*last_entry)
		flist_add_tail(&(*last_entry)->list, &first->next);
}

/*
 * Deflates the next input given, creating as many new packets in the
 * linked list as necessary.
 */
static int __deflate_pdu_buffer(void *next_in, unsigned int next_sz, void **out_pdu,
				struct sk_entry **last_entry, z_stream *stream,
				struct sk_entry *first)
{
	int ret;

	stream->next_in = next_in;
	stream->avail_in = next_sz;
	do {
		if (!stream->avail_out) {
			__fio_net_prep_tail(stream, *out_pdu, last_entry, first);
			if (*last_entry == NULL)
				return 1;

			*out_pdu = malloc(FIO_SERVER_MAX_FRAGMENT_PDU);

			stream->avail_out = FIO_SERVER_MAX_FRAGMENT_PDU;
			stream->next_out = *out_pdu;
		}

		ret = deflate(stream, Z_BLOCK);

		if (ret < 0) {
			free(*out_pdu);
			return 1;
		}
	} while (stream->avail_in);

	return 0;
}

static int __fio_append_iolog_gz_hist(struct sk_entry *first, struct io_log *log,
				      struct io_logs *cur_log, z_stream *stream)
{
	struct sk_entry *entry;
	void *out_pdu;
	int ret, i, j;
	int sample_sz = log_entry_sz(log);

	out_pdu = malloc(FIO_SERVER_MAX_FRAGMENT_PDU);
	stream->avail_out = FIO_SERVER_MAX_FRAGMENT_PDU;
	stream->next_out = out_pdu;

	for (i = 0; i < cur_log->nr_samples; i++) {
		struct io_sample *s;
		struct io_u_plat_entry *cur_plat_entry, *prev_plat_entry;
		uint64_t *cur_plat, *prev_plat;

		s = get_sample(log, cur_log, i);
		ret = __deflate_pdu_buffer(s, sample_sz, &out_pdu, &entry, stream, first);
		if (ret)
			return ret;

		/* Do the subtraction on server side so that client doesn't have to
		 * reconstruct our linked list from packets.
		 */
		cur_plat_entry  = s->data.plat_entry;
		prev_plat_entry = flist_first_entry(&cur_plat_entry->list, struct io_u_plat_entry, list);
		cur_plat  = cur_plat_entry->io_u_plat;
		prev_plat = prev_plat_entry->io_u_plat;

		for (j = 0; j < FIO_IO_U_PLAT_NR; j++) {
			cur_plat[j] -= prev_plat[j];
		}

		flist_del(&prev_plat_entry->list);
		free(prev_plat_entry);

		ret = __deflate_pdu_buffer(cur_plat_entry, sizeof(*cur_plat_entry),
					   &out_pdu, &entry, stream, first);

		if (ret)
			return ret;
	}

	__fio_net_prep_tail(stream, out_pdu, &entry, first);
	return entry == NULL;
}

static int __fio_append_iolog_gz(struct sk_entry *first, struct io_log *log,
				 struct io_logs *cur_log, z_stream *stream)
{
	unsigned int this_len;
	void *out_pdu;
	int ret;

	if (log->log_type == IO_LOG_TYPE_HIST)
		return __fio_append_iolog_gz_hist(first, log, cur_log, stream);

	stream->next_in = (void *) cur_log->log;
	stream->avail_in = cur_log->nr_samples * log_entry_sz(log);

	do {
		struct sk_entry *entry;

		/*
		 * Dirty - since the log is potentially huge, compress it into
		 * FIO_SERVER_MAX_FRAGMENT_PDU chunks and let the receiving
		 * side defragment it.
		 */
		out_pdu = malloc(FIO_SERVER_MAX_FRAGMENT_PDU);

		stream->avail_out = FIO_SERVER_MAX_FRAGMENT_PDU;
		stream->next_out = out_pdu;
		ret = deflate(stream, Z_BLOCK);
		/* may be Z_OK, or Z_STREAM_END */
		if (ret < 0) {
			free(out_pdu);
			return 1;
		}

		this_len = FIO_SERVER_MAX_FRAGMENT_PDU - stream->avail_out;

		entry = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, out_pdu, this_len,
					 NULL, SK_F_VEC | SK_F_INLINE | SK_F_FREE);
		if (!entry) {
			free(out_pdu);
			return 1;
		}
		flist_add_tail(&entry->list, &first->next);
	} while (stream->avail_in);

	return 0;
}

static int fio_append_iolog_gz(struct sk_entry *first, struct io_log *log)
{
	z_stream stream = {
		.zalloc	= Z_NULL,
		.zfree	= Z_NULL,
		.opaque	= Z_NULL,
	};
	int ret = 0;

	if (deflateInit(&stream, Z_DEFAULT_COMPRESSION) != Z_OK)
		return 1;

	while (!flist_empty(&log->io_logs)) {
		struct io_logs *cur_log;

		cur_log = flist_first_entry(&log->io_logs, struct io_logs, list);
		flist_del_init(&cur_log->list);

		ret = __fio_append_iolog_gz(first, log, cur_log, &stream);
		if (ret)
			break;
	}

	ret = deflate(&stream, Z_FINISH);

	while (ret != Z_STREAM_END) {
		struct sk_entry *entry;
		unsigned int this_len;
		void *out_pdu;

		out_pdu = malloc(FIO_SERVER_MAX_FRAGMENT_PDU);
		stream.avail_out = FIO_SERVER_MAX_FRAGMENT_PDU;
		stream.next_out = out_pdu;

		ret = deflate(&stream, Z_FINISH);
		/* may be Z_OK, or Z_STREAM_END */
		if (ret < 0) {
			free(out_pdu);
			break;
		}

		this_len = FIO_SERVER_MAX_FRAGMENT_PDU - stream.avail_out;

		entry = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, out_pdu, this_len,
					 NULL, SK_F_VEC | SK_F_INLINE | SK_F_FREE);
		if (!entry) {
			free(out_pdu);
			break;
		}
		flist_add_tail(&entry->list, &first->next);
	} while (ret != Z_STREAM_END);

	ret = deflateEnd(&stream);
	if (ret == Z_OK)
		return 0;

	return 1;
}
#else
static int fio_append_iolog_gz(struct sk_entry *first, struct io_log *log)
{
	return 1;
}
#endif

static int fio_append_gz_chunks(struct sk_entry *first, struct io_log *log)
{
	struct sk_entry *entry;
	struct flist_head *node;
	int ret = 0;

	pthread_mutex_lock(&log->chunk_lock);
	flist_for_each(node, &log->chunk_list) {
		struct iolog_compress *c;

		c = flist_entry(node, struct iolog_compress, list);
		entry = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, c->buf, c->len,
						NULL, SK_F_VEC | SK_F_INLINE);
		if (!entry) {
			ret = 1;
			break;
		}
		flist_add_tail(&entry->list, &first->next);
	}
	pthread_mutex_unlock(&log->chunk_lock);
	return ret;
}

static int fio_append_text_log(struct sk_entry *first, struct io_log *log)
{
	struct sk_entry *entry;
	int ret = 0;

	while (!flist_empty(&log->io_logs)) {
		struct io_logs *cur_log;
		size_t size;

		cur_log = flist_first_entry(&log->io_logs, struct io_logs, list);
		flist_del_init(&cur_log->list);

		size = cur_log->nr_samples * log_entry_sz(log);

		entry = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, cur_log->log, size,
						NULL, SK_F_VEC | SK_F_INLINE);
		if (!entry) {
			ret = 1;
			break;
		}
		flist_add_tail(&entry->list, &first->next);
	}

	return ret;
}

int fio_send_iolog(struct thread_data *td, struct io_log *log, const char *name)
{
	struct cmd_iolog_pdu pdu = {
		.nr_samples		= cpu_to_le64(iolog_nr_samples(log)),
		.thread_number		= cpu_to_le32(td->thread_number),
		.log_type		= cpu_to_le32(log->log_type),
		.log_hist_coarseness	= cpu_to_le32(log->hist_coarseness),
	};
	struct sk_entry *first;
	struct flist_head *entry;
	int ret = 0;

	if (!flist_empty(&log->chunk_list))
		pdu.compressed = __cpu_to_le32(STORE_COMPRESSED);
	else if (use_zlib)
		pdu.compressed = __cpu_to_le32(XMIT_COMPRESSED);
	else
		pdu.compressed = 0;

	snprintf((char *) pdu.name, sizeof(pdu.name), "%s", name);

	/*
	 * We can't do this for a pre-compressed log, but for that case,
	 * log->nr_samples is zero anyway.
	 */
	flist_for_each(entry, &log->io_logs) {
		struct io_logs *cur_log;
		int i;

		cur_log = flist_entry(entry, struct io_logs, list);

		for (i = 0; i < cur_log->nr_samples; i++) {
			struct io_sample *s = get_sample(log, cur_log, i);

			s->time		= cpu_to_le64(s->time);
			s->data.val	= cpu_to_le64(s->data.val);
			s->__ddir	= __cpu_to_le32(s->__ddir);
			s->bs		= cpu_to_le64(s->bs);

			if (log->log_offset) {
				struct io_sample_offset *so = (void *) s;

				so->offset = cpu_to_le64(so->offset);
			}
		}
	}

	/*
	 * Assemble header entry first
	 */
	first = fio_net_prep_cmd(FIO_NET_CMD_IOLOG, &pdu, sizeof(pdu), NULL, SK_F_VEC | SK_F_INLINE | SK_F_COPY);
	if (!first)
		return 1;

	/*
	 * Now append actual log entries. If log compression was enabled on
	 * the job, just send out the compressed chunks directly. If we
	 * have a plain log, compress if we can, then send. Otherwise, send
	 * the plain text output.
	 */
	if (!flist_empty(&log->chunk_list))
		ret = fio_append_gz_chunks(first, log);
	else if (use_zlib)
		ret = fio_append_iolog_gz(first, log);
	else
		ret = fio_append_text_log(first, log);

	fio_net_queue_entry(first);
	return ret;
}

void fio_server_send_add_job(struct thread_data *td)
{
	struct cmd_add_job_pdu pdu = {
		.thread_number = cpu_to_le32(td->thread_number),
		.groupid = cpu_to_le32(td->groupid),
	};

	convert_thread_options_to_net(&pdu.top, &td->o);

	fio_net_queue_cmd(FIO_NET_CMD_ADD_JOB, &pdu, sizeof(pdu), NULL,
				SK_F_COPY);
}

void fio_server_send_start(struct thread_data *td)
{
	struct sk_out *sk_out = pthread_getspecific(sk_out_key);

	assert(sk_out->sk != -1);

	fio_net_queue_cmd(FIO_NET_CMD_SERVER_START, NULL, 0, NULL, SK_F_SIMPLE);
}

int fio_server_get_verify_state(const char *name, int threadnumber,
				void **datap)
{
	struct thread_io_list *s;
	struct cmd_sendfile out;
	struct cmd_reply *rep;
	uint64_t tag;
	void *data;
	int ret;

	dprint(FD_NET, "server: request verify state\n");

	rep = smalloc(sizeof(*rep));
	if (!rep)
		return ENOMEM;

	__fio_sem_init(&rep->lock, FIO_SEM_LOCKED);
	rep->data = NULL;
	rep->error = 0;

	verify_state_gen_name((char *) out.path, sizeof(out.path), name, me,
				threadnumber);
	tag = (uint64_t) (uintptr_t) rep;
	fio_net_queue_cmd(FIO_NET_CMD_SENDFILE, &out, sizeof(out), &tag,
				SK_F_COPY);

	/*
	 * Wait for the backend to receive the reply
	 */
	if (fio_sem_down_timeout(&rep->lock, 10000)) {
		log_err("fio: timed out waiting for reply\n");
		ret = ETIMEDOUT;
		goto fail;
	}

	if (rep->error) {
		log_err("fio: failure on receiving state file %s: %s\n",
				out.path, strerror(rep->error));
		ret = rep->error;
fail:
		*datap = NULL;
		sfree(rep);
		fio_net_queue_quit();
		return ret;
	}

	/*
	 * The format is verify_state_hdr, then thread_io_list. Verify
	 * the header, and the thread_io_list checksum
	 */
	s = rep->data + sizeof(struct verify_state_hdr);
	if (verify_state_hdr(rep->data, s)) {
		ret = EILSEQ;
		goto fail;
	}

	/*
	 * Don't need the header from now, copy just the thread_io_list
	 */
	ret = 0;
	rep->size -= sizeof(struct verify_state_hdr);
	data = malloc(rep->size);
	memcpy(data, s, rep->size);
	*datap = data;

	sfree(rep->data);
	__fio_sem_remove(&rep->lock);
	sfree(rep);
	return ret;
}

static int fio_init_server_ip(void)
{
	struct sockaddr *addr;
	socklen_t socklen;
	char buf[80];
	const char *str;
	int sk, opt;

	if (use_ipv6)
		sk = socket(AF_INET6, SOCK_STREAM, 0);
	else
		sk = socket(AF_INET, SOCK_STREAM, 0);

	if (sk < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	opt = 1;
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, (void *)&opt, sizeof(opt)) < 0) {
		log_err("fio: setsockopt(REUSEADDR): %s\n", strerror(errno));
		close(sk);
		return -1;
	}
#ifdef SO_REUSEPORT
	/*
	 * Not fatal if fails, so just ignore it if that happens
	 */
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt))) {
	}
#endif

	if (use_ipv6) {
		void *src = &saddr_in6.sin6_addr;

		addr = (struct sockaddr *) &saddr_in6;
		socklen = sizeof(saddr_in6);
		saddr_in6.sin6_family = AF_INET6;
		str = inet_ntop(AF_INET6, src, buf, sizeof(buf));
	} else {
		void *src = &saddr_in.sin_addr;

		addr = (struct sockaddr *) &saddr_in;
		socklen = sizeof(saddr_in);
		saddr_in.sin_family = AF_INET;
		str = inet_ntop(AF_INET, src, buf, sizeof(buf));
	}

	if (bind(sk, addr, socklen) < 0) {
		log_err("fio: bind: %s\n", strerror(errno));
		log_info("fio: failed with IPv%c %s\n", use_ipv6 ? '6' : '4', str);
		close(sk);
		return -1;
	}

	return sk;
}

static int fio_init_server_sock(void)
{
	struct sockaddr_un addr;
	socklen_t len;
	mode_t mode;
	int sk;

	sk = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sk < 0) {
		log_err("fio: socket: %s\n", strerror(errno));
		return -1;
	}

	mode = umask(000);

	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", bind_sock);

	len = sizeof(addr.sun_family) + strlen(bind_sock) + 1;

	if (bind(sk, (struct sockaddr *) &addr, len) < 0) {
		log_err("fio: bind: %s\n", strerror(errno));
		close(sk);
		return -1;
	}

	umask(mode);
	return sk;
}

static int fio_init_server_connection(void)
{
	char bind_str[128];
	int sk;

	dprint(FD_NET, "starting server\n");

	if (!bind_sock)
		sk = fio_init_server_ip();
	else
		sk = fio_init_server_sock();

	if (sk < 0)
		return sk;

	memset(bind_str, 0, sizeof(bind_str));

	if (!bind_sock) {
		char *p, port[16];
		void *src;
		int af;

		if (use_ipv6) {
			af = AF_INET6;
			src = &saddr_in6.sin6_addr;
		} else {
			af = AF_INET;
			src = &saddr_in.sin_addr;
		}

		p = (char *) inet_ntop(af, src, bind_str, sizeof(bind_str));

		sprintf(port, ",%u", fio_net_port);
		if (p)
			strcat(p, port);
		else
			snprintf(bind_str, sizeof(bind_str), "%s", port);
	} else
		snprintf(bind_str, sizeof(bind_str), "%s", bind_sock);

	log_info("fio: server listening on %s\n", bind_str);

	if (listen(sk, 4) < 0) {
		log_err("fio: listen: %s\n", strerror(errno));
		close(sk);
		return -1;
	}

	return sk;
}

int fio_server_parse_host(const char *host, int ipv6, struct in_addr *inp,
			  struct in6_addr *inp6)

{
	int ret = 0;

	if (ipv6)
		ret = inet_pton(AF_INET6, host, inp6);
	else
		ret = inet_pton(AF_INET, host, inp);

	if (ret != 1) {
		struct addrinfo *res, hints = {
			.ai_family = ipv6 ? AF_INET6 : AF_INET,
			.ai_socktype = SOCK_STREAM,
		};

		ret = getaddrinfo(host, NULL, &hints, &res);
		if (ret) {
			log_err("fio: failed to resolve <%s> (%s)\n", host,
					gai_strerror(ret));
			return 1;
		}

		if (ipv6)
			memcpy(inp6, &((struct sockaddr_in6 *) res->ai_addr)->sin6_addr, sizeof(*inp6));
		else
			memcpy(inp, &((struct sockaddr_in *) res->ai_addr)->sin_addr, sizeof(*inp));

		ret = 1;
		freeaddrinfo(res);
	}

	return !(ret == 1);
}

/*
 * Parse a host/ip/port string. Reads from 'str'.
 *
 * Outputs:
 *
 * For IPv4:
 *	*ptr is the host, *port is the port, inp is the destination.
 * For IPv6:
 *	*ptr is the host, *port is the port, inp6 is the dest, and *ipv6 is 1.
 * For local domain sockets:
 *	*ptr is the filename, *is_sock is 1.
 */
int fio_server_parse_string(const char *str, char **ptr, bool *is_sock,
			    int *port, struct in_addr *inp,
			    struct in6_addr *inp6, int *ipv6)
{
	const char *host = str;
	char *portp;
	int lport = 0;

	*ptr = NULL;
	*is_sock = false;
	*port = fio_net_port;
	*ipv6 = 0;

	if (!strncmp(str, "sock:", 5)) {
		*ptr = strdup(str + 5);
		*is_sock = true;

		return 0;
	}

	/*
	 * Is it ip:<ip or host>:port
	 */
	if (!strncmp(host, "ip:", 3))
		host += 3;
	else if (!strncmp(host, "ip4:", 4))
		host += 4;
	else if (!strncmp(host, "ip6:", 4)) {
		host += 4;
		*ipv6 = 1;
	} else if (host[0] == ':') {
		/* String is :port */
		host++;
		lport = atoi(host);
		if (!lport || lport > 65535) {
			log_err("fio: bad server port %u\n", lport);
			return 1;
		}
		/* no hostname given, we are done */
		*port = lport;
		return 0;
	}

	/*
	 * If no port seen yet, check if there's a last ',' at the end
	 */
	if (!lport) {
		portp = strchr(host, ',');
		if (portp) {
			*portp = '\0';
			portp++;
			lport = atoi(portp);
			if (!lport || lport > 65535) {
				log_err("fio: bad server port %u\n", lport);
				return 1;
			}
		}
	}

	if (lport)
		*port = lport;

	if (!strlen(host))
		return 0;

	*ptr = strdup(host);

	if (fio_server_parse_host(*ptr, *ipv6, inp, inp6)) {
		free(*ptr);
		*ptr = NULL;
		return 1;
	}

	if (*port == 0)
		*port = fio_net_port;

	return 0;
}

/*
 * Server arg should be one of:
 *
 * sock:/path/to/socket
 *   ip:1.2.3.4
 *      1.2.3.4
 *
 * Where sock uses unix domain sockets, and ip binds the server to
 * a specific interface. If no arguments are given to the server, it
 * uses IP and binds to 0.0.0.0.
 *
 */
static int fio_handle_server_arg(void)
{
	int port = fio_net_port;
	bool is_sock;
	int ret = 0;

	saddr_in.sin_addr.s_addr = htonl(INADDR_ANY);

	if (!fio_server_arg)
		goto out;

	ret = fio_server_parse_string(fio_server_arg, &bind_sock, &is_sock,
					&port, &saddr_in.sin_addr,
					&saddr_in6.sin6_addr, &use_ipv6);

	if (!is_sock && bind_sock) {
		free(bind_sock);
		bind_sock = NULL;
	}

out:
	fio_net_port = port;
	saddr_in.sin_port = htons(port);
	saddr_in6.sin6_port = htons(port);
	return ret;
}

static void sig_int(int sig)
{
	if (bind_sock)
		unlink(bind_sock);
}

static void set_sig_handlers(void)
{
	struct sigaction act = {
		.sa_handler = sig_int,
		.sa_flags = SA_RESTART,
	};

	sigaction(SIGINT, &act, NULL);
}

void fio_server_destroy_sk_key(void)
{
	pthread_key_delete(sk_out_key);
}

int fio_server_create_sk_key(void)
{
	if (pthread_key_create(&sk_out_key, NULL)) {
		log_err("fio: can't create sk_out backend key\n");
		return 1;
	}

	pthread_setspecific(sk_out_key, NULL);
	return 0;
}

static int fio_server(void)
{
	int sk, ret;

	dprint(FD_NET, "starting server\n");

	if (fio_handle_server_arg())
		return -1;

	sk = fio_init_server_connection();
	if (sk < 0)
		return -1;

	set_sig_handlers();

	ret = accept_loop(sk);

	close(sk);

	if (fio_server_arg) {
		free(fio_server_arg);
		fio_server_arg = NULL;
	}
	if (bind_sock)
		free(bind_sock);

	return ret;
}

void fio_server_got_signal(int signal)
{
	struct sk_out *sk_out = pthread_getspecific(sk_out_key);

	assert(sk_out);

	if (signal == SIGPIPE)
		sk_out->sk = -1;
	else {
		log_info("\nfio: terminating on signal %d\n", signal);
		exit_backend = true;
	}
}

static int check_existing_pidfile(const char *pidfile)
{
	struct stat sb;
	char buf[16];
	pid_t pid;
	FILE *f;

	if (stat(pidfile, &sb))
		return 0;

	f = fopen(pidfile, "r");
	if (!f)
		return 0;

	if (fread(buf, sb.st_size, 1, f) <= 0) {
		fclose(f);
		return 1;
	}
	fclose(f);

	pid = atoi(buf);
	if (kill(pid, SIGCONT) < 0)
		return errno != ESRCH;

	return 1;
}

static int write_pid(pid_t pid, const char *pidfile)
{
	FILE *fpid;

	fpid = fopen(pidfile, "w");
	if (!fpid) {
		log_err("fio: failed opening pid file %s\n", pidfile);
		return 1;
	}

	fprintf(fpid, "%u\n", (unsigned int) pid);
	fclose(fpid);
	return 0;
}

/*
 * If pidfile is specified, background us.
 */
int fio_start_server(char *pidfile)
{
	pid_t pid;
	int ret;

#if defined(WIN32)
	WSADATA wsd;
	WSAStartup(MAKEWORD(2, 2), &wsd);
#endif

	if (!pidfile)
		return fio_server();

	if (check_existing_pidfile(pidfile)) {
		log_err("fio: pidfile %s exists and server appears alive\n",
								pidfile);
		free(pidfile);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		log_err("fio: failed server fork: %s\n", strerror(errno));
		free(pidfile);
		return -1;
	} else if (pid) {
		ret = write_pid(pid, pidfile);
		free(pidfile);
		_exit(ret);
	}

	setsid();
	openlog("fio", LOG_NDELAY|LOG_NOWAIT|LOG_PID, LOG_USER);
	log_syslog = true;
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	f_out = NULL;
	f_err = NULL;

	ret = fio_server();

	closelog();
	unlink(pidfile);
	free(pidfile);
	return ret;
}

void fio_server_set_arg(const char *arg)
{
	fio_server_arg = strdup(arg);
}
