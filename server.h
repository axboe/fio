#ifndef FIO_SERVER_H
#define FIO_SERVER_H

#include <inttypes.h>
#include <string.h>

#include "stat.h"
#include "os/os.h"

/*
 * On-wire encoding is little endian
 */
struct fio_net_cmd {
	uint16_t version;	/* protocol version */
	uint16_t opcode;	/* command opcode */
	uint32_t flags;		/* modifier flags */
	uint64_t serial;	/* serial number */
	uint32_t pdu_len;	/* length of post-cmd layload */
	/*
	 * These must be immediately before the payload, anything before
	 * these fields are checksummed.
	 */
	uint16_t cmd_crc16;	/* cmd checksum */
	uint16_t pdu_crc16;	/* payload checksum */
	uint8_t payload[0];	/* payload */
};

enum {
	FIO_SERVER_VER		= 1,
	FIO_SERVER_VER1		= 1,

	FIO_SERVER_MAX_PDU	= 64,

	FIO_NET_CMD_QUIT	= 1,
	FIO_NET_CMD_EXIT	= 2,
	FIO_NET_CMD_JOB		= 3,
	FIO_NET_CMD_JOBLINE	= 4,
	FIO_NET_CMD_TEXT	= 5,
	FIO_NET_CMD_TS		= 6,
	FIO_NET_CMD_GS		= 7,
	FIO_NET_CMD_ETA		= 8,
	FIO_NET_CMD_PROBE	= 9,
	FIO_NET_CMD_START	= 10,
	FIO_NET_CMD_STOP	= 11,

	FIO_NET_CMD_F_MORE	= 1UL << 0,

	/* crc does not include the crc fields */
	FIO_NET_CMD_CRC_SZ	= sizeof(struct fio_net_cmd) -
					2 * sizeof(uint16_t),

	FIO_NET_CMD_JOBLINE_ARGV	= 128,
};

struct cmd_ts_pdu {
	struct thread_stat ts;
	struct group_run_stats rs;
};

struct cmd_probe_pdu {
	uint8_t hostname[64];
	uint8_t bigendian;
	uint8_t fio_major;
	uint8_t fio_minor;
	uint8_t fio_patch;
};

struct cmd_line_pdu {
	uint16_t argc;
	uint8_t argv[FIO_NET_CMD_JOBLINE_ARGV][64];
};

extern int fio_start_server(int);
extern int fio_server_text_output(const char *, unsigned int len);
extern int fio_server_log(const char *format, ...);
extern int fio_net_send_cmd(int, uint16_t, const void *, off_t);
extern int fio_net_send_simple_cmd(int sk, uint16_t opcode, uint64_t serial);

struct thread_stat;
struct group_run_stats;
extern void fio_server_send_ts(struct thread_stat *, struct group_run_stats *);
extern void fio_server_send_gs(struct group_run_stats *);
extern void fio_server_send_status(void);
extern void fio_server_idle_loop(void);

extern int fio_clients_connect(void);
extern int fio_clients_send_ini(const char *);
extern int fio_handle_clients(void);
extern void fio_client_add(const char *);
extern int fio_client_add_cmd_option(const char *, const char *);

extern int fio_recv_data(int sk, void *p, unsigned int len);
extern int fio_send_data(int sk, const void *p, unsigned int len);
extern void fio_net_cmd_crc(struct fio_net_cmd *);
extern struct fio_net_cmd *fio_net_recv_cmd(int sk);

extern int exit_backend;
extern int fio_net_port;

static inline void fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
				    const void *pdu, uint32_t pdu_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->version	= __cpu_to_le16(FIO_SERVER_VER1);
	cmd->opcode	= cpu_to_le16(opcode);

	if (pdu) {
		cmd->pdu_len	= cpu_to_le32(pdu_len);
		memcpy(&cmd->payload, pdu, pdu_len);
	}
}

#endif
