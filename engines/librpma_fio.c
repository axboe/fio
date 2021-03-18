/*
 * librpma_fio: librpma_apm and librpma_gpspm engines' common part.
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

#include "librpma_fio.h"

#include <libpmem.h>

struct fio_option librpma_fio_options[] = {
	{
		.name	= "serverip",
		.lname	= "rpma_server_ip",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct librpma_fio_options_values, server_ip),
		.help	= "IP address the server is listening on",
		.def	= "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= "port",
		.lname	= "rpma_server port",
		.type	= FIO_OPT_STR_STORE,
		.off1	= offsetof(struct librpma_fio_options_values, port),
		.help	= "port the server is listening on",
		.def	= "7204",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= "direct_write_to_pmem",
		.lname	= "Direct Write to PMem (via RDMA) from the remote host is possible",
		.type	= FIO_OPT_BOOL,
		.off1	= offsetof(struct librpma_fio_options_values,
					direct_write_to_pmem),
		.help	= "Set to true ONLY when Direct Write to PMem from the remote host is possible (https://pmem.io/rpma/documentation/basic-direct-write-to-pmem.html)",
		.def	= "",
		.category = FIO_OPT_C_ENGINE,
		.group	= FIO_OPT_G_LIBRPMA,
	},
	{
		.name	= NULL,
	},
};

int librpma_fio_td_port(const char *port_base_str, struct thread_data *td,
		char *port_out)
{
	unsigned long int port_ul = strtoul(port_base_str, NULL, 10);
	unsigned int port_new;

	port_out[0] = '\0';

	if (port_ul == ULONG_MAX) {
		td_verror(td, errno, "strtoul");
		return -1;
	}
	port_ul += td->thread_number - 1;
	if (port_ul >= UINT_MAX) {
		log_err("[%u] port number (%lu) bigger than UINT_MAX\n",
			td->thread_number, port_ul);
		return -1;
	}

	port_new = port_ul;
	snprintf(port_out, LIBRPMA_FIO_PORT_STR_LEN_MAX - 1, "%u", port_new);

	return 0;
}

char *librpma_fio_allocate_dram(struct thread_data *td, size_t size,
	struct librpma_fio_mem *mem)
{
	char *mem_ptr = NULL;
	int ret;

	if ((ret = posix_memalign((void **)&mem_ptr, page_size, size))) {
		log_err("fio: posix_memalign() failed\n");
		td_verror(td, ret, "posix_memalign");
		return NULL;
	}

	mem->mem_ptr = mem_ptr;
	mem->size_mmap = 0;

	return mem_ptr;
}

char *librpma_fio_allocate_pmem(struct thread_data *td, const char *filename,
		size_t size, struct librpma_fio_mem *mem)
{
	size_t size_mmap = 0;
	char *mem_ptr = NULL;
	int is_pmem = 0;
	size_t ws_offset;

	if (size % page_size) {
		log_err("fio: size (%zu) is not aligned to page size (%zu)\n",
			size, page_size);
		return NULL;
	}

	ws_offset = (td->thread_number - 1) * size;

	if (!filename) {
		log_err("fio: filename is not set\n");
		return NULL;
	}

	/* map the file */
	mem_ptr = pmem_map_file(filename, 0 /* len */, 0 /* flags */,
			0 /* mode */, &size_mmap, &is_pmem);
	if (mem_ptr == NULL) {
		log_err("fio: pmem_map_file(%s) failed\n", filename);
		/* pmem_map_file() sets errno on failure */
		td_verror(td, errno, "pmem_map_file");
		return NULL;
	}

	/* pmem is expected */
	if (!is_pmem) {
		log_err("fio: %s is not located in persistent memory\n",
			filename);
		goto err_unmap;
	}

	/* check size of allocated persistent memory */
	if (size_mmap < ws_offset + size) {
		log_err(
			"fio: %s is too small to handle so many threads (%zu < %zu)\n",
			filename, size_mmap, ws_offset + size);
		goto err_unmap;
	}

	log_info("fio: size of memory mapped from the file %s: %zu\n",
		filename, size_mmap);

	mem->mem_ptr = mem_ptr;
	mem->size_mmap = size_mmap;

	return mem_ptr + ws_offset;

err_unmap:
	(void) pmem_unmap(mem_ptr, size_mmap);
	return NULL;
}

void librpma_fio_free(struct librpma_fio_mem *mem)
{
	if (mem->size_mmap)
		(void) pmem_unmap(mem->mem_ptr, mem->size_mmap);
	else
		free(mem->mem_ptr);
}

#define LIBRPMA_FIO_RETRY_MAX_NO	10
#define LIBRPMA_FIO_RETRY_DELAY_S	5

int librpma_fio_client_init(struct thread_data *td,
		struct rpma_conn_cfg *cfg)
{
	struct librpma_fio_client_data *ccd;
	struct librpma_fio_options_values *o = td->eo;
	struct ibv_context *dev = NULL;
	char port_td[LIBRPMA_FIO_PORT_STR_LEN_MAX];
	struct rpma_conn_req *req = NULL;
	enum rpma_conn_event event;
	struct rpma_conn_private_data pdata;
	enum rpma_log_level log_level_aux = RPMA_LOG_LEVEL_WARNING;
	int remote_flush_type;
	int retry;
	int ret;

	/* --debug=net sets RPMA_LOG_THRESHOLD_AUX to RPMA_LOG_LEVEL_INFO */
#ifdef FIO_INC_DEBUG
	if ((1UL << FD_NET) & fio_debug)
		log_level_aux = RPMA_LOG_LEVEL_INFO;
#endif

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, log_level_aux);

	/* obtain an IBV context for a remote IP address */
	if ((ret = rpma_utils_get_ibv_context(o->server_ip,
			RPMA_UTIL_IBV_CONTEXT_REMOTE, &dev))) {
		librpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		return -1;
	}

	/* allocate client's data */
	ccd = calloc(1, sizeof(*ccd));
	if (ccd == NULL) {
		td_verror(td, errno, "calloc");
		return -1;
	}

	/* allocate all in-memory queues */
	ccd->io_us_queued = calloc(td->o.iodepth, sizeof(*ccd->io_us_queued));
	if (ccd->io_us_queued == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_ccd;
	}

	ccd->io_us_flight = calloc(td->o.iodepth, sizeof(*ccd->io_us_flight));
	if (ccd->io_us_flight == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_io_u_queues;
	}

	ccd->io_us_completed = calloc(td->o.iodepth,
			sizeof(*ccd->io_us_completed));
	if (ccd->io_us_completed == NULL) {
		td_verror(td, errno, "calloc");
		goto err_free_io_u_queues;
	}

	/* create a new peer object */
	if ((ret = rpma_peer_new(dev, &ccd->peer))) {
		librpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_io_u_queues;
	}

	/* create a connection request */
	if (librpma_fio_td_port(o->port, td, port_td))
		goto err_peer_delete;

	for (retry = 0; retry < LIBRPMA_FIO_RETRY_MAX_NO; retry++) {
		if ((ret = rpma_conn_req_new(ccd->peer, o->server_ip, port_td,
				cfg, &req))) {
			librpma_td_verror(td, ret, "rpma_conn_req_new");
			goto err_peer_delete;
		}

		/*
		 * Connect the connection request
		 * and obtain the connection object.
		 */
		if ((ret = rpma_conn_req_connect(&req, NULL, &ccd->conn))) {
			librpma_td_verror(td, ret, "rpma_conn_req_connect");
			goto err_req_delete;
		}

		/* wait for the connection to establish */
		if ((ret = rpma_conn_next_event(ccd->conn, &event))) {
			librpma_td_verror(td, ret, "rpma_conn_next_event");
			goto err_conn_delete;
		} else if (event == RPMA_CONN_ESTABLISHED) {
			break;
		} else if (event == RPMA_CONN_REJECTED) {
			(void) rpma_conn_disconnect(ccd->conn);
			(void) rpma_conn_delete(&ccd->conn);
			if (retry < LIBRPMA_FIO_RETRY_MAX_NO - 1) {
				log_err("Thread [%d]: Retrying (#%i) ...\n",
					td->thread_number, retry + 1);
				sleep(LIBRPMA_FIO_RETRY_DELAY_S);
			} else {
				log_err(
					"Thread [%d]: The maximum number of retries exceeded. Closing.\n",
					td->thread_number);
			}
		} else {
			log_err(
				"rpma_conn_next_event returned an unexptected event: (%s != RPMA_CONN_ESTABLISHED)\n",
				rpma_utils_conn_event_2str(event));
			goto err_conn_delete;
		}
	}

	if (retry > 0)
		log_err("Thread [%d]: Connected after retry #%i\n",
			td->thread_number, retry);

	if (ccd->conn == NULL)
		goto err_peer_delete;

	/* get the connection's private data sent from the server */
	if ((ret = rpma_conn_get_private_data(ccd->conn, &pdata))) {
		librpma_td_verror(td, ret, "rpma_conn_get_private_data");
		goto err_conn_delete;
	}

	/* get the server's workspace representation */
	ccd->ws = pdata.ptr;

	/* create the server's memory representation */
	if ((ret = rpma_mr_remote_from_descriptor(&ccd->ws->descriptor[0],
			ccd->ws->mr_desc_size, &ccd->server_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_from_descriptor");
		goto err_conn_delete;
	}

	/* get the total size of the shared server memory */
	if ((ret = rpma_mr_remote_get_size(ccd->server_mr, &ccd->ws_size))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_get_size");
		goto err_conn_delete;
	}

	/* get flush type of the remote node */
	if ((ret = rpma_mr_remote_get_flush_type(ccd->server_mr,
			&remote_flush_type))) {
		librpma_td_verror(td, ret, "rpma_mr_remote_get_flush_type");
		goto err_conn_delete;
	}

	ccd->server_mr_flush_type =
		(remote_flush_type & RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT) ?
		RPMA_FLUSH_TYPE_PERSISTENT : RPMA_FLUSH_TYPE_VISIBILITY;

	/*
	 * Assure an io_us buffer allocation is page-size-aligned which is required
	 * to register for RDMA. User-provided value is intentionally ignored.
	 */
	td->o.mem_align = page_size;

	td->io_ops_data = ccd;

	return 0;

err_conn_delete:
	(void) rpma_conn_disconnect(ccd->conn);
	(void) rpma_conn_delete(&ccd->conn);

err_req_delete:
	(void) rpma_conn_req_delete(&req);

err_peer_delete:
	(void) rpma_peer_delete(&ccd->peer);

err_free_io_u_queues:
	free(ccd->io_us_queued);
	free(ccd->io_us_flight);
	free(ccd->io_us_completed);

err_free_ccd:
	free(ccd);

	return -1;
}

void librpma_fio_client_cleanup(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	enum rpma_conn_event ev;
	int ret;

	if (ccd == NULL)
		return;

	/* delete the iou's memory registration */
	if ((ret = rpma_mr_dereg(&ccd->orig_mr)))
		librpma_td_verror(td, ret, "rpma_mr_dereg");
	/* delete the iou's memory registration */
	if ((ret = rpma_mr_remote_delete(&ccd->server_mr)))
		librpma_td_verror(td, ret, "rpma_mr_remote_delete");
	/* initiate disconnection */
	if ((ret = rpma_conn_disconnect(ccd->conn)))
		librpma_td_verror(td, ret, "rpma_conn_disconnect");
	/* wait for disconnection to end up */
	if ((ret = rpma_conn_next_event(ccd->conn, &ev))) {
		librpma_td_verror(td, ret, "rpma_conn_next_event");
	} else if (ev != RPMA_CONN_CLOSED) {
		log_err(
			"client_cleanup received an unexpected event (%s != RPMA_CONN_CLOSED)\n",
			rpma_utils_conn_event_2str(ev));
	}
	/* delete the connection */
	if ((ret = rpma_conn_delete(&ccd->conn)))
		librpma_td_verror(td, ret, "rpma_conn_delete");
	/* delete the peer */
	if ((ret = rpma_peer_delete(&ccd->peer)))
		librpma_td_verror(td, ret, "rpma_peer_delete");
	/* free the software queues */
	free(ccd->io_us_queued);
	free(ccd->io_us_flight);
	free(ccd->io_us_completed);
	free(ccd);
	td->io_ops_data = NULL; /* zero ccd */
}

int librpma_fio_file_nop(struct thread_data *td, struct fio_file *f)
{
	/* NOP */
	return 0;
}

int librpma_fio_client_post_init(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd =  td->io_ops_data;
	size_t io_us_size;
	int ret;

	/*
	 * td->orig_buffer is not aligned. The engine requires aligned io_us
	 * so FIO alignes up the address using the formula below.
	 */
	ccd->orig_buffer_aligned = PTR_ALIGN(td->orig_buffer, page_mask) +
			td->o.mem_align;

	/*
	 * td->orig_buffer_size beside the space really consumed by io_us
	 * has paddings which can be omitted for the memory registration.
	 */
	io_us_size = (unsigned long long)td_max_bs(td) *
			(unsigned long long)td->o.iodepth;

	if ((ret = rpma_mr_reg(ccd->peer, ccd->orig_buffer_aligned, io_us_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC |
			RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT, &ccd->orig_mr)))
		librpma_td_verror(td, ret, "rpma_mr_reg");
	return ret;
}

int librpma_fio_client_get_file_size(struct thread_data *td,
		struct fio_file *f)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;

	f->real_file_size = ccd->ws_size;
	fio_file_set_size_known(f);

	return 0;
}

static enum fio_q_status client_queue_sync(struct thread_data *td,
		struct io_u *io_u)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct rpma_completion cmpl;
	unsigned io_u_index;
	int ret;

	/* execute io_u */
	if (io_u->ddir == DDIR_READ) {
		/* post an RDMA read operation */
		if (librpma_fio_client_io_read(td, io_u,
				RPMA_F_COMPLETION_ALWAYS))
			goto err;
	} else if (io_u->ddir == DDIR_WRITE) {
		/* post an RDMA write operation */
		if (librpma_fio_client_io_write(td, io_u))
			goto err;
		if (ccd->flush(td, io_u, io_u, io_u->xfer_buflen))
			goto err;
	} else {
		log_err("unsupported IO mode: %s\n", io_ddir_name(io_u->ddir));
		goto err;
	}

	do {
		/* get a completion */
		ret = rpma_conn_completion_get(ccd->conn, &cmpl);
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			continue;
		} else if (ret != 0) {
			/* an error occurred */
			librpma_td_verror(td, ret, "rpma_conn_completion_get");
			goto err;
		}

		/* if io_us has completed with an error */
		if (cmpl.op_status != IBV_WC_SUCCESS)
			goto err;

		if (cmpl.op == RPMA_OP_SEND)
			++ccd->op_send_completed;
		else {
			if (cmpl.op == RPMA_OP_RECV)
				++ccd->op_recv_completed;

			break;
		}
	} while (1);

	if (ccd->get_io_u_index(&cmpl, &io_u_index) != 1)
		goto err;

	if (io_u->index != io_u_index) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		goto err;
	}

	/* make sure all SENDs are completed before exit - clean up SQ */
	if (librpma_fio_client_io_complete_all_sends(td))
		goto err;

	return FIO_Q_COMPLETED;

err:
	io_u->error = -1;
	return FIO_Q_COMPLETED;
}

enum fio_q_status librpma_fio_client_queue(struct thread_data *td,
		struct io_u *io_u)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;

	if (ccd->io_u_queued_nr == (int)td->o.iodepth)
		return FIO_Q_BUSY;

	if (td->o.sync_io)
		return client_queue_sync(td, io_u);

	/* io_u -> queued[] */
	ccd->io_us_queued[ccd->io_u_queued_nr] = io_u;
	ccd->io_u_queued_nr++;

	return FIO_Q_QUEUED;
}

int librpma_fio_client_commit(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	int flags = RPMA_F_COMPLETION_ON_ERROR;
	struct timespec now;
	bool fill_time;
	int i;
	struct io_u *flush_first_io_u = NULL;
	unsigned long long int flush_len = 0;

	if (!ccd->io_us_queued)
		return -1;

	/* execute all io_us from queued[] */
	for (i = 0; i < ccd->io_u_queued_nr; i++) {
		struct io_u *io_u = ccd->io_us_queued[i];

		if (io_u->ddir == DDIR_READ) {
			if (i + 1 == ccd->io_u_queued_nr ||
			    ccd->io_us_queued[i + 1]->ddir == DDIR_WRITE)
				flags = RPMA_F_COMPLETION_ALWAYS;
			/* post an RDMA read operation */
			if (librpma_fio_client_io_read(td, io_u, flags))
				return -1;
		} else if (io_u->ddir == DDIR_WRITE) {
			/* post an RDMA write operation */
			if (librpma_fio_client_io_write(td, io_u))
				return -1;

			/* cache the first io_u in the sequence */
			if (flush_first_io_u == NULL)
				flush_first_io_u = io_u;

			/*
			 * the flush length is the sum of all io_u's creating
			 * the sequence
			 */
			flush_len += io_u->xfer_buflen;

			/*
			 * if io_u's are random the rpma_flush is required
			 * after each one of them
			 */
			if (!td_random(td)) {
				/*
				 * When the io_u's are sequential and
				 * the current io_u is not the last one and
				 * the next one is also a write operation
				 * the flush can be postponed by one io_u and
				 * cover all of them which build a continuous
				 * sequence.
				 */
				if ((i + 1 < ccd->io_u_queued_nr) &&
				    (ccd->io_us_queued[i + 1]->ddir == DDIR_WRITE))
					continue;
			}

			/* flush all writes which build a continuous sequence */
			if (ccd->flush(td, flush_first_io_u, io_u, flush_len))
				return -1;

			/*
			 * reset the flush parameters in preparation for
			 * the next one
			 */
			flush_first_io_u = NULL;
			flush_len = 0;
		} else {
			log_err("unsupported IO mode: %s\n",
				io_ddir_name(io_u->ddir));
			return -1;
		}
	}

	if ((fill_time = fio_fill_issue_time(td)))
		fio_gettime(&now, NULL);

	/* move executed io_us from queued[] to flight[] */
	for (i = 0; i < ccd->io_u_queued_nr; i++) {
		struct io_u *io_u = ccd->io_us_queued[i];

		/* FIO does not do this if the engine is asynchronous */
		if (fill_time)
			memcpy(&io_u->issue_time, &now, sizeof(now));

		/* move executed io_us from queued[] to flight[] */
		ccd->io_us_flight[ccd->io_u_flight_nr] = io_u;
		ccd->io_u_flight_nr++;

		/*
		 * FIO says:
		 * If an engine has the commit hook
		 * it has to call io_u_queued() itself.
		 */
		io_u_queued(td, io_u);
	}

	/* FIO does not do this if an engine has the commit hook. */
	io_u_mark_submit(td, ccd->io_u_queued_nr);
	ccd->io_u_queued_nr = 0;

	return 0;
}

/*
 * RETURN VALUE
 * - > 0  - a number of completed io_us
 * -   0  - when no complicitions received
 * - (-1) - when an error occurred
 */
static int client_getevent_process(struct thread_data *td)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct rpma_completion cmpl;
	/* io_u->index of completed io_u (cmpl.op_context) */
	unsigned int io_u_index;
	/* # of completed io_us */
	int cmpl_num = 0;
	/* helpers */
	struct io_u *io_u;
	int i;
	int ret;

	/* get a completion */
	if ((ret = rpma_conn_completion_get(ccd->conn, &cmpl))) {
		/* lack of completion is not an error */
		if (ret == RPMA_E_NO_COMPLETION) {
			/* lack of completion is not an error */
			return 0;
		}

		/* an error occurred */
		librpma_td_verror(td, ret, "rpma_conn_completion_get");
		return -1;
	}

	/* if io_us has completed with an error */
	if (cmpl.op_status != IBV_WC_SUCCESS) {
		td->error = cmpl.op_status;
		return -1;
	}

	if (cmpl.op == RPMA_OP_SEND)
		++ccd->op_send_completed;
	else if (cmpl.op == RPMA_OP_RECV)
		++ccd->op_recv_completed;

	if ((ret = ccd->get_io_u_index(&cmpl, &io_u_index)) != 1)
		return ret;

	/* look for an io_u being completed */
	for (i = 0; i < ccd->io_u_flight_nr; ++i) {
		if (ccd->io_us_flight[i]->index == io_u_index) {
			cmpl_num = i + 1;
			break;
		}
	}

	/* if no matching io_u has been found */
	if (cmpl_num == 0) {
		log_err(
			"no matching io_u for received completion found (io_u_index=%u)\n",
			io_u_index);
		return -1;
	}

	/* move completed io_us to the completed in-memory queue */
	for (i = 0; i < cmpl_num; ++i) {
		/* get and prepare io_u */
		io_u = ccd->io_us_flight[i];

		/* append to the queue */
		ccd->io_us_completed[ccd->io_u_completed_nr] = io_u;
		ccd->io_u_completed_nr++;
	}

	/* remove completed io_us from the flight queue */
	for (i = cmpl_num; i < ccd->io_u_flight_nr; ++i)
		ccd->io_us_flight[i - cmpl_num] = ccd->io_us_flight[i];
	ccd->io_u_flight_nr -= cmpl_num;

	return cmpl_num;
}

int librpma_fio_client_getevents(struct thread_data *td, unsigned int min,
		unsigned int max, const struct timespec *t)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	/* total # of completed io_us */
	int cmpl_num_total = 0;
	/* # of completed io_us from a single event */
	int cmpl_num;

	do {
		cmpl_num = client_getevent_process(td);
		if (cmpl_num > 0) {
			/* new completions collected */
			cmpl_num_total += cmpl_num;
		} else if (cmpl_num == 0) {
			/*
			 * It is required to make sure that CQEs for SENDs
			 * will flow at least at the same pace as CQEs for RECVs.
			 */
			if (cmpl_num_total >= min &&
			    ccd->op_send_completed >= ccd->op_recv_completed)
				break;

			/*
			 * To reduce CPU consumption one can use
			 * the rpma_conn_completion_wait() function.
			 * Note this greatly increase the latency
			 * and make the results less stable.
			 * The bandwidth stays more or less the same.
			 */
		} else {
			/* an error occurred */
			return -1;
		}

		/*
		 * The expected max can be exceeded if CQEs for RECVs will come up
		 * faster than CQEs for SENDs. But it is required to make sure CQEs for
		 * SENDs will flow at least at the same pace as CQEs for RECVs.
		 */
	} while (cmpl_num_total < max ||
			ccd->op_send_completed < ccd->op_recv_completed);

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

	return cmpl_num_total;
}

struct io_u *librpma_fio_client_event(struct thread_data *td, int event)
{
	struct librpma_fio_client_data *ccd = td->io_ops_data;
	struct io_u *io_u;
	int i;

	/* get the first io_u from the queue */
	io_u = ccd->io_us_completed[0];

	/* remove the first io_u from the queue */
	for (i = 1; i < ccd->io_u_completed_nr; ++i)
		ccd->io_us_completed[i - 1] = ccd->io_us_completed[i];
	ccd->io_u_completed_nr--;

	dprint_io_u(io_u, "client_event");

	return io_u;
}

char *librpma_fio_client_errdetails(struct io_u *io_u)
{
	/* get the string representation of an error */
	enum ibv_wc_status status = io_u->error;
	const char *status_str = ibv_wc_status_str(status);

	char *details = strdup(status_str);
	if (details == NULL) {
		fprintf(stderr, "Error: %s\n", status_str);
		fprintf(stderr, "Fatal error: out of memory. Aborting.\n");
		abort();
	}

	/* FIO frees the returned string when it becomes obsolete */
	return details;
}

int librpma_fio_server_init(struct thread_data *td)
{
	struct librpma_fio_options_values *o = td->eo;
	struct librpma_fio_server_data *csd;
	struct ibv_context *dev = NULL;
	enum rpma_log_level log_level_aux = RPMA_LOG_LEVEL_WARNING;
	int ret = -1;

	/* --debug=net sets RPMA_LOG_THRESHOLD_AUX to RPMA_LOG_LEVEL_INFO */
#ifdef FIO_INC_DEBUG
	if ((1UL << FD_NET) & fio_debug)
		log_level_aux = RPMA_LOG_LEVEL_INFO;
#endif

	/* configure logging thresholds to see more details */
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD, RPMA_LOG_LEVEL_INFO);
	rpma_log_set_threshold(RPMA_LOG_THRESHOLD_AUX, log_level_aux);


	/* obtain an IBV context for a remote IP address */
	if ((ret = rpma_utils_get_ibv_context(o->server_ip,
			RPMA_UTIL_IBV_CONTEXT_LOCAL, &dev))) {
		librpma_td_verror(td, ret, "rpma_utils_get_ibv_context");
		return -1;
	}

	/* allocate server's data */
	csd = calloc(1, sizeof(*csd));
	if (csd == NULL) {
		td_verror(td, errno, "calloc");
		return -1;
	}

	/* create a new peer object */
	if ((ret = rpma_peer_new(dev, &csd->peer))) {
		librpma_td_verror(td, ret, "rpma_peer_new");
		goto err_free_csd;
	}

	td->io_ops_data = csd;

	return 0;

err_free_csd:
	free(csd);

	return -1;
}

void librpma_fio_server_cleanup(struct thread_data *td)
{
	struct librpma_fio_server_data *csd =  td->io_ops_data;
	int ret;

	if (csd == NULL)
		return;

	/* free the peer */
	if ((ret = rpma_peer_delete(&csd->peer)))
		librpma_td_verror(td, ret, "rpma_peer_delete");

	free(csd);
}

int librpma_fio_server_open_file(struct thread_data *td, struct fio_file *f,
		struct rpma_conn_cfg *cfg)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	struct librpma_fio_options_values *o = td->eo;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	struct librpma_fio_workspace ws = {0};
	struct rpma_conn_private_data pdata;
	uint32_t max_msg_num;
	struct rpma_conn_req *conn_req;
	struct rpma_conn *conn;
	struct rpma_mr_local *mr;
	char port_td[LIBRPMA_FIO_PORT_STR_LEN_MAX];
	struct rpma_ep *ep;
	size_t mem_size = td->o.size;
	size_t mr_desc_size;
	void *ws_ptr;
	int usage_mem_type;
	int ret;

	if (!f->file_name) {
		log_err("fio: filename is not set\n");
		return -1;
	}

	/* start a listening endpoint at addr:port */
	if (librpma_fio_td_port(o->port, td, port_td))
		return -1;

	if ((ret = rpma_ep_listen(csd->peer, o->server_ip, port_td, &ep))) {
		librpma_td_verror(td, ret, "rpma_ep_listen");
		return -1;
	}

	if (strcmp(f->file_name, "malloc") == 0) {
		/* allocation from DRAM using posix_memalign() */
		ws_ptr = librpma_fio_allocate_dram(td, mem_size, &csd->mem);
		usage_mem_type = RPMA_MR_USAGE_FLUSH_TYPE_VISIBILITY;
	} else {
		/* allocation from PMEM using pmem_map_file() */
		ws_ptr = librpma_fio_allocate_pmem(td, f->file_name,
				mem_size, &csd->mem);
		usage_mem_type = RPMA_MR_USAGE_FLUSH_TYPE_PERSISTENT;
	}

	if (ws_ptr == NULL)
		goto err_ep_shutdown;

	f->real_file_size = mem_size;

	if ((ret = rpma_mr_reg(csd->peer, ws_ptr, mem_size,
			RPMA_MR_USAGE_READ_DST | RPMA_MR_USAGE_READ_SRC |
			RPMA_MR_USAGE_WRITE_DST | RPMA_MR_USAGE_WRITE_SRC |
			usage_mem_type, &mr))) {
		librpma_td_verror(td, ret, "rpma_mr_reg");
		goto err_free;
	}

	/* get size of the memory region's descriptor */
	if ((ret = rpma_mr_get_descriptor_size(mr, &mr_desc_size))) {
		librpma_td_verror(td, ret, "rpma_mr_get_descriptor_size");
		goto err_mr_dereg;
	}

	/* verify size of the memory region's descriptor */
	if (mr_desc_size > LIBRPMA_FIO_DESCRIPTOR_MAX_SIZE) {
		log_err(
			"size of the memory region's descriptor is too big (max=%i)\n",
			LIBRPMA_FIO_DESCRIPTOR_MAX_SIZE);
		goto err_mr_dereg;
	}

	/* get the memory region's descriptor */
	if ((ret = rpma_mr_get_descriptor(mr, &ws.descriptor[0]))) {
		librpma_td_verror(td, ret, "rpma_mr_get_descriptor");
		goto err_mr_dereg;
	}

	if (cfg != NULL) {
		if ((ret = rpma_conn_cfg_get_rq_size(cfg, &max_msg_num))) {
			librpma_td_verror(td, ret, "rpma_conn_cfg_get_rq_size");
			goto err_mr_dereg;
		}

		/* verify whether iodepth fits into uint16_t */
		if (max_msg_num > UINT16_MAX) {
			log_err("fio: iodepth too big (%u > %u)\n",
				max_msg_num, UINT16_MAX);
			return -1;
		}

		ws.max_msg_num = max_msg_num;
	}

	/* prepare a workspace description */
	ws.direct_write_to_pmem = o->direct_write_to_pmem;
	ws.mr_desc_size = mr_desc_size;
	pdata.ptr = &ws;
	pdata.len = sizeof(ws);

	/* receive an incoming connection request */
	if ((ret = rpma_ep_next_conn_req(ep, cfg, &conn_req))) {
		librpma_td_verror(td, ret, "rpma_ep_next_conn_req");
		goto err_mr_dereg;
	}

	if (csd->prepare_connection && csd->prepare_connection(td, conn_req))
		goto err_req_delete;

	/* accept the connection request and obtain the connection object */
	if ((ret = rpma_conn_req_connect(&conn_req, &pdata, &conn))) {
		librpma_td_verror(td, ret, "rpma_conn_req_connect");
		goto err_req_delete;
	}

	/* wait for the connection to be established */
	if ((ret = rpma_conn_next_event(conn, &conn_event))) {
		librpma_td_verror(td, ret, "rpma_conn_next_event");
		goto err_conn_delete;
	} else if (conn_event != RPMA_CONN_ESTABLISHED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		goto err_conn_delete;
	}

	/* end-point is no longer needed */
	(void) rpma_ep_shutdown(&ep);

	csd->ws_mr = mr;
	csd->ws_ptr = ws_ptr;
	csd->conn = conn;

	return 0;

err_conn_delete:
	(void) rpma_conn_delete(&conn);

err_req_delete:
	(void) rpma_conn_req_delete(&conn_req);

err_mr_dereg:
	(void) rpma_mr_dereg(&mr);

err_free:
	librpma_fio_free(&csd->mem);

err_ep_shutdown:
	(void) rpma_ep_shutdown(&ep);

	return -1;
}

int librpma_fio_server_close_file(struct thread_data *td, struct fio_file *f)
{
	struct librpma_fio_server_data *csd = td->io_ops_data;
	enum rpma_conn_event conn_event = RPMA_CONN_UNDEFINED;
	int rv = 0;
	int ret;

	/* wait for the connection to be closed */
	ret = rpma_conn_next_event(csd->conn, &conn_event);
	if (!ret && conn_event != RPMA_CONN_CLOSED) {
		log_err("rpma_conn_next_event returned an unexptected event\n");
		rv = -1;
	}

	if ((ret = rpma_conn_disconnect(csd->conn))) {
		librpma_td_verror(td, ret, "rpma_conn_disconnect");
		rv = -1;
	}

	if ((ret = rpma_conn_delete(&csd->conn))) {
		librpma_td_verror(td, ret, "rpma_conn_delete");
		rv = -1;
	}

	if ((ret = rpma_mr_dereg(&csd->ws_mr))) {
		librpma_td_verror(td, ret, "rpma_mr_dereg");
		rv = -1;
	}

	librpma_fio_free(&csd->mem);

	return rv;
}
