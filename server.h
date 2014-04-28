#ifndef FIO_SERVER_H
#define FIO_SERVER_H

#include <inttypes.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "stat.h"
#include "os/os.h"
#include "diskutil.h"

#define FIO_NET_PORT 8765

/*
 * On-wire encoding is little endian
 */
struct fio_net_cmd {
	uint16_t version;	/* protocol version */
	uint16_t opcode;	/* command opcode */
	uint32_t flags;		/* modifier flags */
	uint64_t tag;		/* passed back on reply */
	uint32_t pdu_len;	/* length of post-cmd layload */
	/*
	 * These must be immediately before the payload, anything before
	 * these fields are checksummed.
	 */
	uint16_t cmd_crc16;	/* cmd checksum */
	uint16_t pdu_crc16;	/* payload checksum */
	uint8_t payload[];	/* payload */
};

struct fio_net_cmd_reply {
	struct flist_head list;
	struct timeval tv;
	uint64_t saved_tag;
	uint16_t opcode;
};

enum {
	FIO_SERVER_VER			= 34,

	FIO_SERVER_MAX_FRAGMENT_PDU	= 1024,
	FIO_SERVER_MAX_CMD_MB		= 2048,

	FIO_NET_CMD_QUIT		= 1,
	FIO_NET_CMD_EXIT		= 2,
	FIO_NET_CMD_JOB			= 3,
	FIO_NET_CMD_JOBLINE		= 4,
	FIO_NET_CMD_TEXT		= 5,
	FIO_NET_CMD_TS			= 6,
	FIO_NET_CMD_GS			= 7,
	FIO_NET_CMD_SEND_ETA		= 8,
	FIO_NET_CMD_ETA			= 9,
	FIO_NET_CMD_PROBE		= 10,
	FIO_NET_CMD_START		= 11,
	FIO_NET_CMD_STOP		= 12,
	FIO_NET_CMD_DU			= 13,
	FIO_NET_CMD_SERVER_START	= 14,
	FIO_NET_CMD_ADD_JOB		= 15,
	FIO_NET_CMD_RUN			= 16,
	FIO_NET_CMD_IOLOG		= 17,
	FIO_NET_CMD_UPDATE_JOB		= 18,
	FIO_NET_CMD_NR			= 19,

	FIO_NET_CMD_F_MORE		= 1UL << 0,

	/* crc does not include the crc fields */
	FIO_NET_CMD_CRC_SZ		= sizeof(struct fio_net_cmd) -
						2 * sizeof(uint16_t),

	FIO_NET_NAME_MAX		= 256,

	FIO_NET_CLIENT_TIMEOUT		= 5000,

	FIO_PROBE_FLAG_ZLIB		= 1UL << 0,
};

struct cmd_ts_pdu {
	struct thread_stat ts;
	struct group_run_stats rs;
};

struct cmd_du_pdu {
	struct disk_util_stat dus;
	struct disk_util_agg agg;
};

struct cmd_client_probe_pdu {
	uint64_t flags;
};

struct cmd_probe_reply_pdu {
	uint8_t hostname[64];
	uint8_t bigendian;
	uint8_t fio_version[32];
	uint8_t os;
	uint8_t arch;
	uint8_t bpp;
	uint32_t cpus;
	uint64_t flags;
};

struct cmd_single_line_pdu {
	uint16_t len;
	uint8_t text[];
};

struct cmd_line_pdu {
	uint16_t lines;
	uint16_t client_type;
	struct cmd_single_line_pdu options[];
};

struct cmd_job_pdu {
	uint32_t buf_len;
	uint32_t client_type;
	uint8_t buf[0];
};

struct cmd_start_pdu {
	uint32_t jobs;
	uint32_t stat_outputs;
};

struct cmd_end_pdu {
	uint32_t error;
	uint32_t signal;
};

struct cmd_add_job_pdu {
	uint32_t thread_number;
	uint32_t groupid;
	struct thread_options_pack top;
};

struct cmd_text_pdu {
	uint32_t level;
	uint32_t buf_len;
	uint64_t log_sec;
	uint64_t log_usec;
	uint8_t buf[0];
};

struct cmd_iolog_pdu {
	uint32_t thread_number;
	uint32_t nr_samples;
	uint32_t log_type;
	uint32_t compressed;
	uint8_t name[FIO_NET_NAME_MAX];
	struct io_sample samples[0];
};

extern int fio_start_server(char *);
extern int fio_server_text_output(int, const char *, size_t);
extern int fio_net_send_cmd(int, uint16_t, const void *, off_t, uint64_t *, struct flist_head *);
extern int fio_net_send_simple_cmd(int, uint16_t, uint64_t, struct flist_head *);
extern void fio_server_set_arg(const char *);
extern int fio_server_parse_string(const char *, char **, int *, int *, struct in_addr *, struct in6_addr *, int *);
extern int fio_server_parse_host(const char *, int, struct in_addr *, struct in6_addr *);
extern const char *fio_server_op(unsigned int);
extern void fio_server_got_signal(int);

struct thread_stat;
struct group_run_stats;
extern void fio_server_send_ts(struct thread_stat *, struct group_run_stats *);
extern void fio_server_send_gs(struct group_run_stats *);
extern void fio_server_send_du(void);
extern void fio_server_idle_loop(void);

extern int fio_clients_connect(void);
extern int fio_clients_send_ini(const char *);
extern void fio_client_add_cmd_option(void *, const char *);
extern void fio_client_add_ini_file(void *, const char *);

extern int fio_recv_data(int sk, void *p, unsigned int len);
extern int fio_send_data(int sk, const void *p, unsigned int len);
extern void fio_net_cmd_crc(struct fio_net_cmd *);
extern void fio_net_cmd_crc_pdu(struct fio_net_cmd *, const void *);
extern struct fio_net_cmd *fio_net_recv_cmd(int sk);

extern int fio_send_iolog(struct thread_data *, struct io_log *, const char *);
extern void fio_server_send_add_job(struct thread_data *);
extern void fio_server_send_start(struct thread_data *);
extern int fio_net_send_stop(int sk, int error, int signal);
extern int fio_net_send_quit(int sk);

extern int exit_backend;
extern int fio_net_port;

static inline void __fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
				      uint32_t pdu_len, uint64_t tag)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->version	= __cpu_to_le16(FIO_SERVER_VER);
	cmd->opcode	= cpu_to_le16(opcode);
	cmd->tag	= cpu_to_le64(tag);
	cmd->pdu_len	= cpu_to_le32(pdu_len);
}


static inline void fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
				    const void *pdu, uint32_t pdu_len,
				    uint64_t tag)
{
	__fio_init_net_cmd(cmd, opcode, pdu_len, tag);

	if (pdu)
		memcpy(&cmd->payload, pdu, pdu_len);
}

#endif
