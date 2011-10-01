#ifndef FIO_SERVER_H
#define FIO_SERVER_H

#include <inttypes.h>
#include <string.h>
#include <endian.h>

/*
 * On-wire encoding is little endian
 */
struct fio_net_cmd {
	uint16_t version;	/* protocol version */
	uint16_t opcode;	/* command opcode */
	uint32_t flags;		/* modifier flags */
	uint64_t serial;	/* serial number */
	uint32_t pdu_len;	/* length of post-cmd layload */
	uint16_t cmd_crc16;	/* cmd checksum */
	uint16_t pdu_crc16;	/* payload checksum */
	uint8_t payload[0];	/* payload */
};

enum {
	FIO_SERVER_VER		= 1,
	FIO_SERVER_VER1		= 1,

	FIO_SERVER_MAX_PDU	= 64,

	FIO_NET_CMD_QUIT	= 1,
	FIO_NET_CMD_JOB		= 2,
	FIO_NET_CMD_ACK		= 3,
	FIO_NET_CMD_NAK		= 4,
	FIO_NET_CMD_TEXT	= 5,

	FIO_NET_CMD_F_MORE	= 1,

	/* crc does not include the crc fields */
	FIO_NET_CMD_CRC_SZ	= sizeof(struct fio_net_cmd) -
					2 * sizeof(uint16_t),
};

extern int fio_server(void);
extern int fio_server_text_output(const char *, unsigned int len);
extern int fio_server_log(const char *format, ...);
extern int fio_net_send_cmd(int, uint16_t, const char *, off_t);

extern int fio_clients_connect(void);
extern int fio_clients_send_ini(const char *);
extern int fio_handle_clients(void);
extern void fio_client_add(const char *);

extern int fio_recv_data(int sk, void *p, unsigned int len);
extern int fio_send_data(int sk, const void *p, unsigned int len);
extern void fio_net_cmd_crc(struct fio_net_cmd *);
extern struct fio_net_cmd *fio_net_cmd_read(int sk);

extern int exit_backend;
extern int fio_net_port;

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define le16_to_cpu(x)		(x)
#define le32_to_cpu(x)		(x)
#define le64_to_cpu(x)		(x)
#define cpu_to_le16(x)		(x)
#define cpu_to_le32(x)		(x)
#define cpu_to_le64(x)		(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define le16_to_cpu(x)		__bswap_16(x)
#define le32_to_cpu(x)		__bswap_32(x)
#define le64_to_cpu(x)		__bswap_64(x)
#define cpu_to_le16(x)		__bswap_16(x)
#define cpu_to_le32(x)		__bswap_32(x)
#define cpu_to_le64(x)		__bswap_64(x)
#else
#error "Endianness not detected"
#endif

static inline void fio_init_net_cmd(struct fio_net_cmd *cmd, uint16_t opcode,
				    const void *pdu, uint32_t pdu_len)
{
	memset(cmd, 0, sizeof(*cmd));

	cmd->version	= cpu_to_le16(FIO_SERVER_VER1);
	cmd->opcode	= cpu_to_le16(opcode);

	if (pdu) {
		cmd->pdu_len	= cpu_to_le32(pdu_len);
		memcpy(&cmd->payload, pdu, pdu_len);
	}
}

#endif
