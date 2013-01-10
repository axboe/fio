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
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>

#include "fio.h"
#include "server.h"
#include "crc/crc16.h"
#include "lib/ieee754.h"

int fio_net_port = 8765;

int exit_backend = 0;

static int server_fd = -1;
static char *fio_server_arg;
static char *bind_sock;
static struct sockaddr_in saddr_in;
static struct sockaddr_in6 saddr_in6;
static int first_cmd_check;
static int use_ipv6;

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
	"RUN",
};

const char *fio_server_op(unsigned int op)
{
	static char buf[32];

	if (op < FIO_NET_CMD_NR)
		return fio_server_ops[op];

	sprintf(buf, "UNKNOWN/%d", op);
	return buf;
}

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
		else
			break;
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
		else
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
		ret = fio_recv_data(sk, &cmd, sizeof(cmd));
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

		cmdret = realloc(cmdret, cmd_size);

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
		pdu = (void *) cmdret->payload + pdu_offset;
		ret = fio_recv_data(sk, pdu, cmd.pdu_len);
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
		if (cmdret->pdu_len && (cmdret->opcode == FIO_NET_CMD_TEXT ||
		    cmdret->opcode == FIO_NET_CMD_JOB)) {
			char *buf = (char *) cmdret->payload;

			buf[cmdret->pdu_len ] = '\0';
		}
		/* frag flag is internal */
		cmdret->flags &= ~FIO_NET_CMD_F_MORE;
	}

	return cmdret;
}

void fio_net_cmd_crc(struct fio_net_cmd *cmd)
{
	uint32_t pdu_len;

	cmd->cmd_crc16 = __cpu_to_le16(fio_crc16(cmd, FIO_NET_CMD_CRC_SZ));

	pdu_len = le32_to_cpu(cmd->pdu_len);
	if (pdu_len)
		cmd->pdu_crc16 = __cpu_to_le16(fio_crc16(cmd->payload, pdu_len));
}

int fio_net_send_cmd(int fd, uint16_t opcode, const void *buf, off_t size,
		     uint64_t tag)
{
	struct fio_net_cmd *cmd = NULL;
	size_t this_len, cur_len = 0;
	int ret;

	do {
		this_len = size;
		if (this_len > FIO_SERVER_MAX_PDU)
			this_len = FIO_SERVER_MAX_PDU;

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

	if (cmd)
		free(cmd);

	return ret;
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
	struct fio_net_int_cmd *cmd;
	int ret;

	if (!list)
		return fio_net_send_simple_stack_cmd(sk, opcode, tag);

	cmd = malloc(sizeof(*cmd));

	fio_init_net_cmd(&cmd->cmd, opcode, NULL, 0, (uintptr_t) cmd);
	fio_net_cmd_crc(&cmd->cmd);

	INIT_FLIST_HEAD(&cmd->list);
	fio_gettime(&cmd->tv, NULL);
	cmd->saved_tag = tag;

	ret = fio_send_data(sk, &cmd->cmd, sizeof(cmd->cmd));
	if (ret) {
		free(cmd);
		return ret;
	}

	flist_add_tail(&cmd->list, list);
	return 0;
}

static int fio_server_send_quit_cmd(void)
{
	dprint(FD_NET, "server: sending quit\n");
	return fio_net_send_simple_cmd(server_fd, FIO_NET_CMD_QUIT, 0, NULL);
}

static int handle_job_cmd(struct fio_net_cmd *cmd)
{
	char *buf = (char *) cmd->payload;
	struct cmd_start_pdu spdu;
	struct cmd_end_pdu epdu;
	int ret;

	if (parse_jobs_ini(buf, 1, 0)) {
		fio_server_send_quit_cmd();
		return -1;
	}

	spdu.jobs = cpu_to_le32(thread_number);
	spdu.stat_outputs = cpu_to_le32(stat_number);
	fio_net_send_cmd(server_fd, FIO_NET_CMD_START, &spdu, sizeof(spdu), 0);

	ret = fio_backend();

	epdu.error = ret;
	fio_net_send_cmd(server_fd, FIO_NET_CMD_STOP, &epdu, sizeof(epdu), 0);

	fio_server_send_quit_cmd();
	reset_fio_state();
	return ret;
}

static int handle_jobline_cmd(struct fio_net_cmd *cmd)
{
	void *pdu = cmd->payload;
	struct cmd_single_line_pdu *cslp;
	struct cmd_line_pdu *clp;
	unsigned long offset;
	char **argv;
	int ret, i;

	clp = pdu;
	clp->lines = le16_to_cpu(clp->lines);
	argv = malloc(clp->lines * sizeof(char *));
	offset = sizeof(*clp);

	dprint(FD_NET, "server: %d command line args\n", clp->lines);

	for (i = 0; i < clp->lines; i++) {
		cslp = pdu + offset;
		argv[i] = (char *) cslp->text;

		offset += sizeof(*cslp) + le16_to_cpu(cslp->len);
		dprint(FD_NET, "server: %d: %s\n", i, argv[i]);
	}

	if (parse_cmd_line(clp->lines, argv)) {
		fio_server_send_quit_cmd();
		free(argv);
		return -1;
	}

	free(argv);

	fio_net_send_simple_cmd(server_fd, FIO_NET_CMD_START, 0, NULL);

	ret = fio_backend();
	fio_server_send_quit_cmd();
	reset_fio_state();
	return ret;
}

static int handle_probe_cmd(struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu probe;

	dprint(FD_NET, "server: sending probe reply\n");

	memset(&probe, 0, sizeof(probe));
	gethostname((char *) probe.hostname, sizeof(probe.hostname));
#ifdef FIO_BIG_ENDIAN
	probe.bigendian = 1;
#endif
	strncpy((char *) probe.fio_version, fio_version_string, sizeof(probe.fio_version));

	probe.os	= FIO_OS;
	probe.arch	= FIO_ARCH;

	probe.bpp	= sizeof(void *);

	return fio_net_send_cmd(server_fd, FIO_NET_CMD_PROBE, &probe, sizeof(probe), cmd->tag);
}

static int handle_send_eta_cmd(struct fio_net_cmd *cmd)
{
	struct jobs_eta *je;
	size_t size;
	int i;

	if (!thread_number)
		return 0;

	size = sizeof(*je) + thread_number * sizeof(char) + 1;
	je = malloc(size);
	memset(je, 0, size);

	if (!calc_thread_status(je, 1)) {
		free(je);
		return 0;
	}

	dprint(FD_NET, "server sending status\n");

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

	je->elapsed_sec		= cpu_to_le64(je->elapsed_sec);
	je->eta_sec		= cpu_to_le64(je->eta_sec);
	je->is_pow2		= cpu_to_le32(je->is_pow2);

	fio_net_send_cmd(server_fd, FIO_NET_CMD_ETA, je, size, cmd->tag);
	free(je);
	return 0;
}

static int handle_command(struct fio_net_cmd *cmd)
{
	int ret;

	dprint(FD_NET, "server: got op [%s], pdu=%u, tag=%lx\n",
			fio_server_op(cmd->opcode), cmd->pdu_len, cmd->tag);

	switch (cmd->opcode) {
	case FIO_NET_CMD_QUIT:
		fio_terminate_threads(TERMINATE_ALL);
		return -1;
	case FIO_NET_CMD_EXIT:
		exit_backend = 1;
		return -1;
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
	default:
		log_err("fio: unknown opcode: %s\n",fio_server_op(cmd->opcode));
		ret = 1;
	}

	return ret;
}

static int handle_connection(int sk, int block)
{
	struct fio_net_cmd *cmd = NULL;
	int ret = 0;

	/* read forever */
	while (!exit_backend) {
		struct pollfd pfd = {
			.fd	= sk,
			.events	= POLLIN,
		};

		ret = 0;
		do {
			ret = poll(&pfd, 1, 100);
			if (ret < 0) {
				if (errno == EINTR)
					break;
				log_err("fio: poll: %s\n", strerror(errno));
				break;
			} else if (!ret) {
				if (!block)
					return 0;
				continue;
			}

			if (pfd.revents & POLLIN)
				break;
			if (pfd.revents & (POLLERR|POLLHUP)) {
				ret = 1;
				break;
			}
		} while (!exit_backend);

		if (ret < 0)
			break;

		cmd = fio_net_recv_cmd(sk);
		if (!cmd) {
			ret = -1;
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
	if (!first_cmd_check)
		fio_net_send_simple_cmd(server_fd, FIO_NET_CMD_RUN, 0, NULL);
	if (server_fd != -1)
		handle_connection(server_fd, 0);
}

static int accept_loop(int listen_sk)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	struct pollfd pfd;
	int ret, sk, flags, exitval = 0;

	dprint(FD_NET, "server enter accept loop\n");

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

	sk = accept(listen_sk, (struct sockaddr *) &addr, &len);
	if (sk < 0) {
		log_err("fio: accept: %s\n", strerror(errno));
		return -1;
	}

	dprint(FD_NET, "server: connect from %s\n", inet_ntoa(addr.sin_addr));

	server_fd = sk;

	exitval = handle_connection(sk, 1);

	server_fd = -1;
	close(sk);

	if (!exit_backend)
		goto again;

out:
	return exitval;
}

int fio_server_text_output(const char *buf, size_t len)
{
	if (server_fd != -1)
		return fio_net_send_cmd(server_fd, FIO_NET_CMD_TEXT, buf, len, 0);

	return log_local_buf(buf, len);
}

static void convert_io_stat(struct io_stat *dst, struct io_stat *src)
{
	dst->max_val	= cpu_to_le64(src->max_val);
	dst->min_val	= cpu_to_le64(src->min_val);
	dst->samples	= cpu_to_le64(src->samples);

	/*
	 * Encode to IEEE 754 for network transfer
	 */
	dst->mean.u.i	= __cpu_to_le64(fio_double_to_uint64(src->mean.u.f));
	dst->S.u.i	= __cpu_to_le64(fio_double_to_uint64(src->S.u.f));
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

	dprint(FD_NET, "server sending end stats\n");

	memset(&p, 0, sizeof(p));

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

	for (i = 0; i < FIO_IO_U_LIST_MAX_LEN; i++) {
		fio_fp64_t *src = &ts->percentile_list[i];
		fio_fp64_t *dst = &p.ts.percentile_list[i];

		dst->u.i = __cpu_to_le64(fio_double_to_uint64(src->u.f));
	}

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
		p.ts.short_io_u[i]	= cpu_to_le64(ts->short_io_u[i]);
	}

	p.ts.total_submit	= cpu_to_le64(ts->total_submit);
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

	fio_net_send_cmd(server_fd, FIO_NET_CMD_TS, &p, sizeof(p), 0);
}

void fio_server_send_gs(struct group_run_stats *rs)
{
	struct group_run_stats gs;

	dprint(FD_NET, "server sending group run stats\n");

	convert_gs(&gs, rs);
	fio_net_send_cmd(server_fd, FIO_NET_CMD_GS, &gs, sizeof(gs), 0);
}

static void convert_agg(struct disk_util_agg *dst, struct disk_util_agg *src)
{
	int i;

	for (i = 0; i < 2; i++) {
		dst->ios[i]	= cpu_to_le32(src->ios[i]);
		dst->merges[i]	= cpu_to_le32(src->merges[i]);
		dst->sectors[i]	= cpu_to_le64(src->sectors[i]);
		dst->ticks[i]	= cpu_to_le32(src->ticks[i]);
	}

	dst->io_ticks		= cpu_to_le32(src->io_ticks);
	dst->time_in_queue	= cpu_to_le32(src->time_in_queue);
	dst->slavecount		= cpu_to_le32(src->slavecount);
	dst->max_util.u.i	= __cpu_to_le64(fio_double_to_uint64(src->max_util.u.f));
}

static void convert_dus(struct disk_util_stat *dst, struct disk_util_stat *src)
{
	int i;

	strcpy((char *) dst->name, (char *) src->name);

	for (i = 0; i < 2; i++) {
		dst->ios[i]	= cpu_to_le32(src->ios[i]);
		dst->merges[i]	= cpu_to_le32(src->merges[i]);
		dst->sectors[i]	= cpu_to_le64(src->sectors[i]);
		dst->ticks[i]	= cpu_to_le32(src->ticks[i]);
	}

	dst->io_ticks		= cpu_to_le32(src->io_ticks);
	dst->time_in_queue	= cpu_to_le32(src->time_in_queue);
	dst->msec		= cpu_to_le64(src->msec);
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

		fio_net_send_cmd(server_fd, FIO_NET_CMD_DU, &pdu, sizeof(pdu), 0);
	}
}

int fio_server_log(const char *format, ...)
{
	char buffer[1024];
	va_list args;
	size_t len;

	dprint(FD_NET, "server log\n");

	va_start(args, format);
	len = vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	return fio_server_text_output(buffer, len);
}

static int fio_init_server_ip(void)
{
	struct sockaddr *addr;
	socklen_t socklen;
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
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		log_err("fio: setsockopt: %s\n", strerror(errno));
		close(sk);
		return -1;
	}
#ifdef SO_REUSEPORT
	if (setsockopt(sk, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
		log_err("fio: setsockopt: %s\n", strerror(errno));
		close(sk);
		return -1;
	}
#endif

	if (use_ipv6) {
		addr = (struct sockaddr *) &saddr_in6;
		socklen = sizeof(saddr_in6);
		saddr_in6.sin6_family = AF_INET6;
	} else {
		addr = (struct sockaddr *) &saddr_in;
		socklen = sizeof(saddr_in);
		saddr_in.sin_family = AF_INET;
	}

	if (bind(sk, addr, socklen) < 0) {
		log_err("fio: bind: %s\n", strerror(errno));
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

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, bind_sock);
	unlink(bind_sock);

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

	if (!bind_sock) {
		char *p, port[16];
		const void *src;
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
			strcpy(bind_str, port);
	} else
		strcpy(bind_str, bind_sock);

	log_info("fio: server listening on %s\n", bind_str);

	if (listen(sk, 0) < 0) {
		log_err("fio: listen: %s\n", strerror(errno));
		return -1;
	}

	return sk;
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
int fio_server_parse_string(const char *str, char **ptr, int *is_sock,
			    int *port, struct in_addr *inp,
			    struct in6_addr *inp6, int *ipv6)
{
	const char *host = str;
	char *portp;
	int ret, lport = 0;

	*ptr = NULL;
	*is_sock = 0;
	*port = fio_net_port;
	*ipv6 = 0;

	if (!strncmp(str, "sock:", 5)) {
		*ptr = strdup(str + 5);
		*is_sock = 1;

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
			log_err("fio: bad server port %u\n", port);
			return 1;
		}
		/* no hostname given, we are done */
		*port = lport;
		return 0;
	}

	/*
	 * If no port seen yet, check if there's a last ':' at the end
	 */
	if (!lport) {
		portp = strchr(host, ',');
		if (portp) {
			*portp = '\0';
			portp++;
			lport = atoi(portp);
			if (!lport || lport > 65535) {
				log_err("fio: bad server port %u\n", port);
				return 1;
			}
		}
	}

	if (lport)
		*port = lport;

	if (!strlen(host))
		return 0;

	*ptr = strdup(host);

	if (*ipv6)
		ret = inet_pton(AF_INET6, host, inp6);
	else
		ret = inet_pton(AF_INET, host, inp);

	if (ret != 1) {
		struct hostent *hent;

		hent = gethostbyname(host);
		if (!hent) {
			log_err("fio: failed to resolve <%s>\n", host);
			free(*ptr);
			*ptr = NULL;
			return 1;
		}

		if (*ipv6) {
			if (hent->h_addrtype != AF_INET6) {
				log_info("fio: falling back to IPv4\n");
				*ipv6 = 0;
			} else
				memcpy(inp6, hent->h_addr_list[0], 16);
		}
		if (!*ipv6) {
			if (hent->h_addrtype != AF_INET) {
				log_err("fio: lookup type mismatch\n");
				free(*ptr);
				*ptr = NULL;
				return 1;
			}
			memcpy(inp, hent->h_addr_list[0], 4);
		}
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
	int is_sock, ret = 0;

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

static int fio_server(void)
{
	int sk, ret;

	dprint(FD_NET, "starting server\n");

	if (fio_handle_server_arg())
		return -1;

	sk = fio_init_server_connection();
	if (sk < 0)
		return -1;

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
	if (signal == SIGPIPE)
		server_fd = -1;
	else {
		log_info("\nfio: terminating on signal %d\n", signal);
		exit_backend = 1;
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
	WSAStartup(MAKEWORD(2,2), &wsd);
#endif

	if (!pidfile)
		return fio_server();

	if (check_existing_pidfile(pidfile)) {
		log_err("fio: pidfile %s exists and server appears alive\n",
								pidfile);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		log_err("fio: failed server fork: %s", strerror(errno));
		free(pidfile);
		return -1;
	} else if (pid) {
		int ret = write_pid(pid, pidfile);

		exit(ret);
	}

	setsid();
	openlog("fio", LOG_NDELAY|LOG_NOWAIT|LOG_PID, LOG_USER);
	log_syslog = 1;
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
