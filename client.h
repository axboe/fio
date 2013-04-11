#ifndef CLIENT_H
#define CLIENT_H

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "stat.h"

struct fio_net_cmd;
struct client_ops;

enum {
	Client_created		= 0,
	Client_connected	= 1,
	Client_started		= 2,
	Client_running		= 3,
	Client_stopped		= 4,
	Client_exited		= 5,
};

struct fio_client {
	struct flist_head list;
	struct flist_head hash_list;
	struct flist_head arg_list;
	union {
		struct sockaddr_in addr;
		struct sockaddr_in6 addr6;
		struct sockaddr_un addr_un;
	};
	char *hostname;
	int port;
	int fd;
	unsigned int refs;

	char *name;

	int state;

	int skip_newline;
	int is_sock;
	int disk_stats_shown;
	unsigned int jobs;
	unsigned int nr_stat;
	int error;
	int signal;
	int ipv6;
	int sent_job;
	int did_stat;
	uint32_t type;

	uint32_t thread_number;
	uint32_t groupid;

	struct flist_head eta_list;
	struct client_eta *eta_in_flight;

	struct flist_head cmd_list;

	uint16_t argc;
	char **argv;

	struct client_ops *ops;
	void *client_data;

	char **ini_file;
	unsigned int nr_ini_file;
};

struct cmd_iolog_pdu;
typedef void (client_cmd_op)(struct fio_client *, struct fio_net_cmd *);
typedef void (client_eta_op)(struct jobs_eta *je);
typedef void (client_timed_out_op)(struct fio_client *);
typedef void (client_jobs_eta_op)(struct fio_client *client, struct jobs_eta *je);
typedef void (client_iolog_op)(struct fio_client *client, struct cmd_iolog_pdu *);

struct client_ops {
	client_cmd_op		*text;
	client_cmd_op		*disk_util;
	client_cmd_op		*thread_status;
	client_cmd_op		*group_stats;
	client_jobs_eta_op	*jobs_eta;
	client_eta_op		*eta;
	client_cmd_op		*probe;
	client_cmd_op		*quit;
	client_cmd_op		*add_job;
	client_cmd_op		*update_job;
	client_timed_out_op	*timed_out;
	client_cmd_op		*stop;
	client_cmd_op		*start;
	client_cmd_op		*job_start;
	client_iolog_op		*iolog;
	client_timed_out_op	*removed;

	unsigned int eta_msec;
	int stay_connected;
	uint32_t client_type;
};

extern struct client_ops fio_client_ops;

struct client_eta {
	unsigned int pending;
	struct jobs_eta eta;
};

extern int fio_handle_client(struct fio_client *);
extern void fio_client_dec_jobs_eta(struct client_eta *eta, client_eta_op fn);
extern void fio_client_sum_jobs_eta(struct jobs_eta *dst, struct jobs_eta *je);

enum {
	Fio_client_ipv4 = 1,
	Fio_client_ipv6,
	Fio_client_socket,
};

extern int fio_client_connect(struct fio_client *);
extern int fio_clients_connect(void);
extern int fio_start_client(struct fio_client *);
extern int fio_start_all_clients(void);
extern int fio_client_send_ini(struct fio_client *, const char *);
extern int fio_clients_send_ini(const char *);
extern int fio_handle_clients(struct client_ops *);
extern int fio_client_add(struct client_ops *, const char *, void **);
extern struct fio_client *fio_client_add_explicit(struct client_ops *, const char *, int, int);
extern void fio_client_add_cmd_option(void *, const char *);
extern void fio_client_add_ini_file(void *, const char *);
extern int fio_client_terminate(struct fio_client *);
extern void fio_clients_terminate(void);
extern struct fio_client *fio_get_client(struct fio_client *);
extern void fio_put_client(struct fio_client *);
extern int fio_client_update_options(struct fio_client *, struct thread_options *, uint64_t *);
extern int fio_client_wait_for_reply(struct fio_client *, uint64_t);

#define FIO_CLIENT_DEF_ETA_MSEC		900

enum {
	FIO_CLIENT_TYPE_CLI		= 1,
	FIO_CLIENT_TYPE_GUI		= 2,
};

#endif

