#ifndef FIO_SERVER_H
#define FIO_SERVER_H

#include <inttypes.h>
#include <string.h>
#include <endian.h>

#include "stat.h"

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
	FIO_NET_CMD_ACK		= 4,
	FIO_NET_CMD_NAK		= 5,
	FIO_NET_CMD_TEXT	= 6,
	FIO_NET_CMD_TS		= 7,
	FIO_NET_CMD_GS		= 8,

	FIO_NET_CMD_F_MORE	= 1UL << 0,

	/* crc does not include the crc fields */
	FIO_NET_CMD_CRC_SZ	= sizeof(struct fio_net_cmd) -
					2 * sizeof(uint16_t),
};

struct cmd_ts_pdu {
	struct thread_stat ts;
	struct group_run_stats rs;
};

extern int fio_start_server(int);
extern int fio_server_text_output(const char *, unsigned int len);
extern int fio_server_log(const char *format, ...);
extern int fio_net_send_cmd(int, uint16_t, const void *, off_t);

struct thread_stat;
struct group_run_stats;
extern void fio_server_send_ts(struct thread_stat *, struct group_run_stats *);
extern void fio_server_send_gs(struct group_run_stats *);

extern int fio_clients_connect(void);
extern int fio_clients_send_ini(const char *);
extern int fio_handle_clients(void);
extern void fio_client_add(const char *);

extern int fio_recv_data(int sk, void *p, unsigned int len);
extern int fio_send_data(int sk, const void *p, unsigned int len);
extern void fio_net_cmd_crc(struct fio_net_cmd *);
extern struct fio_net_cmd *fio_net_recv_cmd(int sk);

extern int exit_backend;
extern int fio_net_port;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __le16_to_cpu(x)		(x)
#define __le32_to_cpu(x)		(x)
#define __le64_to_cpu(x)		(x)
#define __cpu_to_le16(x)		(x)
#define __cpu_to_le32(x)		(x)
#define __cpu_to_le64(x)		(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __le16_to_cpu(x)		__bswap_16(x)
#define __le32_to_cpu(x)		__bswap_32(x)
#define __le64_to_cpu(x)		__bswap_64(x)
#define __cpu_to_le16(x)		__bswap_16(x)
#define __cpu_to_le32(x)		__bswap_32(x)
#define __cpu_to_le64(x)		__bswap_64(x)
#else
#error "Endianness not detected"
#endif

#define le16_to_cpu(val) ({			\
	uint16_t *__val = &(val);		\
	__le16_to_cpu(*__val);			\
})
#define le32_to_cpu(val) ({			\
	uint32_t *__val = &(val);		\
	__le32_to_cpu(*__val);			\
})
#define le64_to_cpu(val) ({			\
	uint64_t *__val = &(val);		\
	__le64_to_cpu(*__val);			\
})
#define cpu_to_le16(val) ({			\
	uint16_t *__val = &(val);		\
	__cpu_to_le16(*__val);			\
})
#define cpu_to_le32(val) ({			\
	uint32_t *__val = &(val);		\
	__cpu_to_le32(*__val);			\
})
#define cpu_to_le64(val) ({			\
	uint64_t *__val = &(val);		\
	__cpu_to_le64(*__val);			\
})

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
