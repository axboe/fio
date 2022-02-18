/*
 * librpma_fio: librpma_apm and librpma_gpspm engines' common header.
 *
 * Copyright 2021, Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License,
 * version 2 as published by the Free Software Foundation..
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef LIBRPMA_FIO_H
#define LIBRPMA_FIO_H 1

#include "../fio.h"
#include "../optgroup.h"

#include <librpma.h>

/* servers' and clients' common */

#define librpma_td_verror(td, err, func) \
	td_vmsg((td), (err), rpma_err_2str(err), (func))

/* ceil(a / b) = (a + b - 1) / b */
#define LIBRPMA_FIO_CEIL(a, b) (((a) + (b) - 1) / (b))

/* common option structure for server and client */
struct librpma_fio_options_values {
	/*
	 * FIO considers .off1 == 0 absent so the first meaningful field has to
	 * have padding ahead of it.
	 */
	void *pad;
	char *server_ip;
	/* base server listening port */
	char *port;
	/* Direct Write to PMem is possible */
	unsigned int direct_write_to_pmem;
	/* Set to 0 to wait for completion instead of busy-wait polling completion. */
	unsigned int busy_wait_polling;
};

extern struct fio_option librpma_fio_options[];

/*
 * Limited by the maximum length of the private data
 * for rdma_connect() in case of RDMA_PS_TCP (28 bytes).
 */
#define LIBRPMA_FIO_DESCRIPTOR_MAX_SIZE 24

struct librpma_fio_workspace {
	uint16_t max_msg_num;	/* # of RQ slots */
	uint8_t direct_write_to_pmem; /* Direct Write to PMem is possible */
	uint8_t mr_desc_size;	/* size of mr_desc in descriptor[] */
	/* buffer containing mr_desc */
	char descriptor[LIBRPMA_FIO_DESCRIPTOR_MAX_SIZE];
};

#define LIBRPMA_FIO_PORT_STR_LEN_MAX 12

int librpma_fio_td_port(const char *port_base_str, struct thread_data *td,
		char *port_out);

struct librpma_fio_mem {
	/* memory buffer */
	char *mem_ptr;

	/* size of the mapped persistent memory */
	size_t size_mmap;
};

char *librpma_fio_allocate_dram(struct thread_data *td, size_t size,
		struct librpma_fio_mem *mem);

char *librpma_fio_allocate_pmem(struct thread_data *td, struct fio_file *f,
		size_t size, struct librpma_fio_mem *mem);

void librpma_fio_free(struct librpma_fio_mem *mem);

/* clients' common */

typedef int (*librpma_fio_flush_t)(struct thread_data *td,
		struct io_u *first_io_u, struct io_u *last_io_u,
		unsigned long long int len);

/*
 * RETURN VALUE
 * - ( 1) - on success
 * - ( 0) - skip
 * - (-1) - on error
 */
typedef int (*librpma_fio_get_io_u_index_t)(struct ibv_wc *wc,
		unsigned int *io_u_index);

struct librpma_fio_client_data {
	struct rpma_peer *peer;
	struct rpma_conn *conn;
	struct rpma_cq *cq;

	/* aligned td->orig_buffer */
	char *orig_buffer_aligned;

	/* ious's base address memory registration (cd->orig_buffer_aligned) */
	struct rpma_mr_local *orig_mr;

	struct librpma_fio_workspace *ws;

	/* a server's memory representation */
	struct rpma_mr_remote *server_mr;
	enum rpma_flush_type server_mr_flush_type;

	/* remote workspace description */
	size_t ws_size;

	/* in-memory queues */
	struct io_u **io_us_queued;
	int io_u_queued_nr;
	struct io_u **io_us_flight;
	int io_u_flight_nr;
	struct io_u **io_us_completed;
	int io_u_completed_nr;

	/* SQ control. Note: all of them have to be kept in sync. */
	uint32_t op_send_posted;
	uint32_t op_send_completed;
	uint32_t op_recv_completed;

	librpma_fio_flush_t flush;
	librpma_fio_get_io_u_index_t get_io_u_index;

	/* engine-specific client data */
	void *client_data;
};

int librpma_fio_client_init(struct thread_data *td,
		struct rpma_conn_cfg *cfg);
void librpma_fio_client_cleanup(struct thread_data *td);

int librpma_fio_file_nop(struct thread_data *td, struct fio_file *f);
int librpma_fio_client_get_file_size(struct thread_data *td,
		struct fio_file *f);

int librpma_fio_client_post_init(struct thread_data *td);

enum fio_q_status librpma_fio_client_queue(struct thread_data *td,
		struct io_u *io_u);

int librpma_fio_client_commit(struct thread_data *td);

int librpma_fio_client_getevents(struct thread_data *td, unsigned int min,
		unsigned int max, const struct timespec *t);

struct io_u *librpma_fio_client_event(struct thread_data *td, int event);

char *librpma_fio_client_errdetails(struct io_u *io_u);

static inline int librpma_fio_client_io_read(struct thread_data *td,
		struct io_u *io_u, int flags)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	size_t dst_offset = (char *)(io_u->xfer_buf) - ccd->orig_buffer_aligned;
	size_t src_offset = io_u->offset;
	int ret;

	if ((ret = rpma_read(ccd->conn, ccd->orig_mr, dst_offset,
			ccd->server_mr, src_offset, io_u->xfer_buflen,
			flags, (void *)(uintptr_t)io_u->index))) {
		librpma_td_verror(td, ret, "rpma_read");
		return -1;
	}

	return 0;
}

static inline int librpma_fio_client_io_write(struct thread_data *td,
		struct io_u *io_u)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	size_t src_offset = (char *)(io_u->xfer_buf) - ccd->orig_buffer_aligned;
	size_t dst_offset = io_u->offset;
	int ret;

	if ((ret = rpma_write(ccd->conn, ccd->server_mr, dst_offset,
			ccd->orig_mr, src_offset, io_u->xfer_buflen,
			RPMA_F_COMPLETION_ON_ERROR,
			(void *)(uintptr_t)io_u->index))) {
		librpma_td_verror(td, ret, "rpma_write");
		return -1;
	}

	return 0;
}

static inline int librpma_fio_client_io_complete_all_sends(
		struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct ibv_wc wc;
	int ret;

	while (ccd->op_send_posted != ccd->op_send_completed) {
		/* get a completion */
		ret = rpma_cq_get_wc(ccd->cq, 1, &wc, NULL);
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			continue;
		} else if (ret != 0) {
			/* an error occurred */
			librpma_td_verror(td, ret, "rpma_cq_get_wc");
			break;
		}

		if (wc.status != IBV_WC_SUCCESS)
			return -1;

		if (wc.opcode == IBV_WC_SEND)
			++ccd->op_send_completed;
		else {
			log_err(
				"A completion other than IBV_WC_SEND got during cleaning up the CQ from SENDs\n");
			return -1;
		}
	}

	/*
	 * All posted SENDs are completed and RECVs for them (responses) are
	 * completed. This is the initial situation so the counters are reset.
	 */
	if (ccd->op_send_posted == ccd->op_send_completed &&
			ccd->op_send_completed == ccd->op_recv_completed) {
		ccd->op_send_posted = 0;
		ccd->op_send_completed = 0;
		ccd->op_recv_completed = 0;
	}

	return 0;
}

/* servers' common */

typedef int (*librpma_fio_prepare_connection_t)(
		struct thread_data *td,
		struct rpma_conn_req *conn_req);

struct librpma_fio_server_data {
	struct rpma_peer *peer;

	/* resources of an incoming connection */
	struct rpma_conn *conn;
	struct rpma_cq *cq;

	char *ws_ptr;
	struct rpma_mr_local *ws_mr;
	struct librpma_fio_mem mem;

	/* engine-specific server data */
	void *server_data;

	librpma_fio_prepare_connection_t prepare_connection;
};

int librpma_fio_server_init(struct thread_data *td);

void librpma_fio_server_cleanup(struct thread_data *td);

int librpma_fio_server_open_file(struct thread_data *td,
		struct fio_file *f, struct rpma_conn_cfg *cfg);

int librpma_fio_server_close_file(struct thread_data *td,
		struct fio_file *f);

#endif /* LIBRPMA_FIO_H */
