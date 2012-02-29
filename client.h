#ifndef CLIENT_H
#define CLIENT_H

struct fio_client;
struct fio_net_cmd;

typedef void (*client_text_op_func)(struct fio_client *client,
		FILE *f, __u16 pdu_len, const char *buf);

typedef void (*client_disk_util_op_func)(struct fio_client *client, struct fio_net_cmd *cmd);

typedef void (*client_thread_status_op)(struct fio_net_cmd *cmd);

typedef void (*client_group_stats_op)(struct fio_net_cmd *cmd);

typedef void (*client_eta_op)(struct fio_client *client, struct fio_net_cmd *cmd);

typedef void (*client_probe_op)(struct fio_client *client, struct fio_net_cmd *cmd);

typedef void (*client_thread_status_display_op)(char *status_message, double perc);

struct client_ops {
	client_text_op_func text_op;
	client_disk_util_op_func disk_util;
	client_thread_status_op thread_status;
	client_group_stats_op group_stats;
	client_eta_op eta;
	client_probe_op probe;
	client_thread_status_display_op thread_status_display;
};

extern struct client_ops fio_client_ops;

#endif

