/*
 * gfio - gui front end for fio - the flexible io tester
 *
 * Copyright (C) 2012 Stephen M. Cameron <stephenmcameron@gmail.com> 
 *
 * The license below covers all files distributed with fio unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <locale.h>
#include <malloc.h>

#include <glib.h>
#include <gtk/gtk.h>

#include "fio.h"

static void gfio_update_thread_status(char *status_message, double perc);

#define ARRAYSIZE(x) (sizeof((x)) / (sizeof((x)[0])))

typedef void (*clickfunction)(GtkWidget *widget, gpointer data);

static void connect_clicked(GtkWidget *widget, gpointer data);
static void start_job_clicked(GtkWidget *widget, gpointer data);

static struct button_spec {
	const char *buttontext;
	clickfunction f;
	const char *tooltiptext;
	const int start_insensitive;
} buttonspeclist[] = {
#define CONNECT_BUTTON 0
#define START_JOB_BUTTON 1
	{ "Connect", connect_clicked, "Connect to host", 0 },
	{ "Start Job",
		start_job_clicked,
		"Send current fio job to fio server to be executed", 1 },
};

struct probe_widget {
	GtkWidget *hostname;
	GtkWidget *os;
	GtkWidget *arch;
	GtkWidget *fio_ver;
};

struct eta_widget {
	GtkWidget *name;
	GtkWidget *iotype;
	GtkWidget *ioengine;
	GtkWidget *iodepth;
	GtkWidget *jobs;
	GtkWidget *files;
	GtkWidget *read_bw;
	GtkWidget *read_iops;
	GtkWidget *cr_bw;
	GtkWidget *cr_iops;
	GtkWidget *write_bw;
	GtkWidget *write_iops;
	GtkWidget *cw_bw;
	GtkWidget *cw_iops;
};

struct gui {
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *topvbox;
	GtkWidget *topalign;
	GtkWidget *bottomalign;
	GtkWidget *thread_status_pb;
	GtkWidget *buttonbox;
	GtkWidget *button[ARRAYSIZE(buttonspeclist)];
	GtkWidget *scrolled_window;
	GtkWidget *textview;
	GtkWidget *error_info_bar;
	GtkWidget *error_label;
	GtkTextBuffer *text;
	struct probe_widget probe;
	struct eta_widget eta;
	int connected;
	pthread_t t;

	struct fio_client *client;
	int nr_job_files;
	char **job_files;
} ui;

static void clear_ui_info(struct gui *ui)
{
	gtk_label_set_text(GTK_LABEL(ui->probe.hostname), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.os), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.arch), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.fio_ver), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.name), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.iotype), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.ioengine), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.iodepth), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.jobs), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.files), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.read_bw), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.read_iops), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.write_bw), "");
	gtk_label_set_text(GTK_LABEL(ui->eta.write_iops), "");
}

static void gfio_set_connected(struct gui *ui, int connected)
{
	if (connected) {
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
		ui->connected = 1;
		gtk_button_set_label(GTK_BUTTON(ui->button[CONNECT_BUTTON]), "Disconnect");
	} else {
		ui->connected = 0;
		gtk_button_set_label(GTK_BUTTON(ui->button[CONNECT_BUTTON]), "Connect");
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 0);
	}
}

static void gfio_text_op(struct fio_client *client,
                FILE *f, __u16 pdu_len, const char *buf)
{
#if 0
	GtkTextBuffer *buffer;
	GtkTextIter end;

	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ui.textview));
	gdk_threads_enter();
	gtk_text_buffer_get_end_iter(buffer, &end);
	gtk_text_buffer_insert(buffer, &end, buf, -1);
	gdk_threads_leave();
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(ui.textview),
					&end, 0.0, FALSE, 0.0,0.0);
#else
	fio_client_ops.text_op(client, f, pdu_len, buf);
#endif
}

static void gfio_disk_util_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	printf("gfio_disk_util_op called\n");
	fio_client_ops.disk_util(client, cmd);
}

static void gfio_thread_status_op(struct fio_net_cmd *cmd)
{
	printf("gfio_thread_status_op called\n");
	fio_client_ops.thread_status(cmd);
}

static void gfio_group_stats_op(struct fio_net_cmd *cmd)
{
	printf("gfio_group_stats_op called\n");
	fio_client_ops.group_stats(cmd);
}

static void gfio_update_eta(struct jobs_eta *je)
{
	static int eta_good;
	char eta_str[128];
	char output[256];
	char tmp[32];
	double perc = 0.0;
	int i2p = 0;

	eta_str[0] = '\0';
	output[0] = '\0';

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	sprintf(tmp, "%u", je->nr_running);
	gtk_label_set_text(GTK_LABEL(ui.eta.jobs), tmp);
	sprintf(tmp, "%u", je->files_open);
	gtk_label_set_text(GTK_LABEL(ui.eta.files), tmp);

#if 0
	if (je->m_rate[0] || je->m_rate[1] || je->t_rate[0] || je->t_rate[1]) {
	if (je->m_rate || je->t_rate) {
		char *tr, *mr;

		mr = num2str(je->m_rate, 4, 0, i2p);
		tr = num2str(je->t_rate, 4, 0, i2p);
		gtk_label_set_text(GTK_LABEL(ui.eta.
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops || je->t_iops)
		p += sprintf(p, ", CR=%d/%d IOPS", je->t_iops, je->m_iops);

	gtk_label_set_text(GTK_LABEL(ui.eta.cr_bw), "---");
	gtk_label_set_text(GTK_LABEL(ui.eta.cr_iops), "---");
	gtk_label_set_text(GTK_LABEL(ui.eta.cw_bw), "---");
	gtk_label_set_text(GTK_LABEL(ui.eta.cw_iops), "---");
#endif

	if (je->eta_sec != INT_MAX && je->nr_running) {
		char *iops_str[2];
		char *rate_str[2];

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running)
			strcpy(output, "-.-% done");
		else {
			eta_good = 1;
			perc *= 100.0;
			sprintf(output, "%3.1f%% done", perc);
		}

		rate_str[0] = num2str(je->rate[0], 5, 10, i2p);
		rate_str[1] = num2str(je->rate[1], 5, 10, i2p);

		iops_str[0] = num2str(je->iops[0], 4, 1, 0);
		iops_str[1] = num2str(je->iops[1], 4, 1, 0);

		gtk_label_set_text(GTK_LABEL(ui.eta.read_bw), rate_str[0]);
		gtk_label_set_text(GTK_LABEL(ui.eta.read_iops), iops_str[0]);
		gtk_label_set_text(GTK_LABEL(ui.eta.write_bw), rate_str[1]);
		gtk_label_set_text(GTK_LABEL(ui.eta.write_iops), iops_str[1]);

		free(rate_str[0]);
		free(rate_str[1]);
		free(iops_str[0]);
		free(iops_str[1]);
	}

	if (eta_str[0]) {
		char *dst = output + strlen(output);

		sprintf(dst, " - %s", eta_str);
	}
		
	gfio_update_thread_status(output, perc);
}

static void gfio_eta_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct jobs_eta *je = (struct jobs_eta *) cmd->payload;
	struct client_eta *eta = (struct client_eta *) (uintptr_t) cmd->tag;

	client->eta_in_flight = NULL;
	flist_del_init(&client->eta_list);

	fio_client_convert_jobs_eta(je);
	fio_client_sum_jobs_eta(&eta->eta, je);
	fio_client_dec_jobs_eta(eta, gfio_update_eta);
}

static void gfio_probe_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu *probe = (struct cmd_probe_pdu *) cmd->payload;
	const char *os, *arch;
	char buf[64];

	os = fio_get_os_string(probe->os);
	if (!os)
		os = "unknown";

	arch = fio_get_arch_string(probe->arch);
	if (!arch)
		os = "unknown";

	if (!client->name)
		client->name = strdup((char *) probe->hostname);

	gtk_label_set_text(GTK_LABEL(ui.probe.hostname), (char *) probe->hostname);
	gtk_label_set_text(GTK_LABEL(ui.probe.os), os);
	gtk_label_set_text(GTK_LABEL(ui.probe.arch), arch);
	sprintf(buf, "%u.%u.%u", probe->fio_major, probe->fio_minor, probe->fio_patch);
	gtk_label_set_text(GTK_LABEL(ui.probe.fio_ver), buf);
}

static void gfio_update_thread_status(char *status_message, double perc)
{
	static char message[100];
	const char *m = message;

	strncpy(message, status_message, sizeof(message) - 1);
	gtk_progress_bar_set_text(
		GTK_PROGRESS_BAR(ui.thread_status_pb), m);
	gtk_progress_bar_set_fraction(
		GTK_PROGRESS_BAR(ui.thread_status_pb), perc / 100.0);
	gdk_threads_enter();
	gtk_widget_queue_draw(ui.window);
	gdk_threads_leave();
}

static void gfio_quit_op(struct fio_client *client)
{
	struct gui *ui = client->client_data;

	gfio_set_connected(ui, 0);
}

static void gfio_add_job_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_add_job_pdu *p = (struct cmd_add_job_pdu *) cmd->payload;
	struct gui *ui = client->client_data;
	char tmp[8];
	int i;

	p->iodepth		= le32_to_cpu(p->iodepth);
	p->rw			= le32_to_cpu(p->rw);

	for (i = 0; i < 2; i++) {
		p->min_bs[i] 	= le32_to_cpu(p->min_bs[i]);
		p->max_bs[i]	= le32_to_cpu(p->max_bs[i]);
	}

	p->numjobs		= le32_to_cpu(p->numjobs);
	p->group_reporting	= le32_to_cpu(p->group_reporting);

	gtk_label_set_text(GTK_LABEL(ui->eta.name), (gchar *) p->jobname);
	gtk_label_set_text(GTK_LABEL(ui->eta.iotype), ddir_str(p->rw));
	gtk_label_set_text(GTK_LABEL(ui->eta.ioengine), (gchar *) p->ioengine);

	sprintf(tmp, "%u", p->iodepth);
	gtk_label_set_text(GTK_LABEL(ui->eta.iodepth), tmp);
}

static void gfio_client_timed_out(struct fio_client *client)
{
	struct gui *ui = client->client_data;
	GtkWidget *dialog, *label, *content;
	char buf[256];

	gdk_threads_enter();

	gfio_set_connected(ui, 0);
	clear_ui_info(ui);

	sprintf(buf, "Client %s: timeout talking to server.\n", client->hostname);

	dialog = gtk_dialog_new_with_buttons("Timed out!",
			GTK_WINDOW(ui->window),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_OK, NULL);

	content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	label = gtk_label_new((const gchar *) buf);
	gtk_container_add(GTK_CONTAINER(content), label);
	gtk_widget_show_all(dialog);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);

	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);

	gdk_threads_leave();
}

struct client_ops gfio_client_ops = {
	.text_op		= gfio_text_op,
	.disk_util		= gfio_disk_util_op,
	.thread_status		= gfio_thread_status_op,
	.group_stats		= gfio_group_stats_op,
	.eta			= gfio_eta_op,
	.probe			= gfio_probe_op,
	.quit			= gfio_quit_op,
	.add_job		= gfio_add_job_op,
	.timed_out		= gfio_client_timed_out,
	.stay_connected		= 1,
};

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
        gtk_main_quit();
}

static void *job_thread(void *arg)
{
	fio_handle_clients(&gfio_client_ops);
	return NULL;
}

static int send_job_files(struct gui *ui)
{
	int i, ret = 0;

	for (i = 0; i < ui->nr_job_files; i++) {
		ret = fio_clients_send_ini(ui->job_files[i]);
		if (ret)
			break;

		free(ui->job_files[i]);
		ui->job_files[i] = NULL;
	}
	while (i < ui->nr_job_files) {
		free(ui->job_files[i]);
		ui->job_files[i] = NULL;
		i++;
	}

	return ret;
}

static void start_job_thread(struct gui *ui)
{
	if (send_job_files(ui)) {
		printf("Yeah, I didn't really like those options too much.\n");
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
		return;
	}
}

static GtkWidget *new_info_label_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *label_widget;
	GtkWidget *frame;

	frame = gtk_frame_new(label);
	label_widget = gtk_label_new(NULL);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), label_widget);

	return label_widget;
}

static GtkWidget *create_spinbutton(GtkWidget *hbox, double min, double max, double defval)
{
	GtkWidget *button, *box;

	box = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(hbox), box);

	button = gtk_spin_button_new_with_range(min, max, 1.0);
	gtk_box_pack_start(GTK_BOX(box), button, TRUE, TRUE, 0);

	gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(button), GTK_UPDATE_IF_VALID);
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(button), defval);

	return button;
}

static void start_job_clicked(__attribute__((unused)) GtkWidget *widget,
                gpointer data)
{
	struct gui *ui = data;

	gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 0);
	start_job_thread(ui);
}

static void file_open(GtkWidget *w, gpointer data);

static void connect_clicked(GtkWidget *widget, gpointer data)
{
	struct gui *ui = data;

	if (!ui->connected) {
		if (!ui->nr_job_files)
			file_open(widget, data);
		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui->thread_status_pb), "No jobs running");
		fio_clients_connect();
		pthread_create(&ui->t, NULL, job_thread, NULL);
		gfio_set_connected(ui, 1);
	} else {
		fio_clients_terminate();
		gfio_set_connected(ui, 0);
		clear_ui_info(ui);
	}
}

static void add_button(struct gui *ui, int i, GtkWidget *buttonbox,
			struct button_spec *buttonspec)
{
	ui->button[i] = gtk_button_new_with_label(buttonspec->buttontext);
	g_signal_connect(ui->button[i], "clicked", G_CALLBACK (buttonspec->f), ui);
	gtk_box_pack_start(GTK_BOX (ui->buttonbox), ui->button[i], FALSE, FALSE, 3);
	gtk_widget_set_tooltip_text(ui->button[i], buttonspeclist[i].tooltiptext);
	gtk_widget_set_sensitive(ui->button[i], !buttonspec->start_insensitive);
}

static void add_buttons(struct gui *ui,
				struct button_spec *buttonlist,
				int nbuttons)
{
	int i;

	for (i = 0; i < nbuttons; i++)
		add_button(ui, i, ui->buttonbox, &buttonlist[i]);
}

static void on_info_bar_response(GtkWidget *widget, gint response,
                                 gpointer data)
{
	if (response == GTK_RESPONSE_OK) {
		gtk_widget_destroy(widget);
		ui.error_info_bar = NULL;
	}
}

void report_error(GError *error)
{
	if (ui.error_info_bar == NULL) {
		ui.error_info_bar = gtk_info_bar_new_with_buttons(GTK_STOCK_OK,
		                                               GTK_RESPONSE_OK,
		                                               NULL);
		g_signal_connect(ui.error_info_bar, "response", G_CALLBACK(on_info_bar_response), NULL);
		gtk_info_bar_set_message_type(GTK_INFO_BAR(ui.error_info_bar),
		                              GTK_MESSAGE_ERROR);
		
		ui.error_label = gtk_label_new(error->message);
		GtkWidget *container = gtk_info_bar_get_content_area(GTK_INFO_BAR(ui.error_info_bar));
		gtk_container_add(GTK_CONTAINER(container), ui.error_label);
		
		gtk_box_pack_start(GTK_BOX(ui.vbox), ui.error_info_bar, FALSE, FALSE, 0);
		gtk_widget_show_all(ui.vbox);
	} else {
		char buffer[256];
		snprintf(buffer, sizeof(buffer), "Failed to open file.");
		gtk_label_set(GTK_LABEL(ui.error_label), buffer);
	}
}

static int get_connection_details(char **host, int *port, int *type,
				  int *server_start)
{
	GtkWidget *dialog, *box, *vbox, *hentry, *hbox, *frame, *pentry, *combo;
	GtkWidget *button;
	char *typeentry;

	dialog = gtk_dialog_new_with_buttons("Connection details",
			GTK_WINDOW(ui.window),
			GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL);

	frame = gtk_frame_new("Hostname / socket name");
	vbox = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	box = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), box);

	hbox = gtk_hbox_new(TRUE, 10);
	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);
	hentry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(hentry), "localhost");
	gtk_box_pack_start(GTK_BOX(hbox), hentry, TRUE, TRUE, 0);

	frame = gtk_frame_new("Port");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	box = gtk_vbox_new(FALSE, 10);
	gtk_container_add(GTK_CONTAINER(frame), box);

	hbox = gtk_hbox_new(TRUE, 4);
	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);
	pentry = create_spinbutton(hbox, 1, 65535, FIO_NET_PORT);

	frame = gtk_frame_new("Type");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	box = gtk_vbox_new(FALSE, 10);
	gtk_container_add(GTK_CONTAINER(frame), box);

	hbox = gtk_hbox_new(TRUE, 4);
	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);

	combo = gtk_combo_box_text_new();
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "IPv4");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "IPv6");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), "local socket");
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

	gtk_container_add(GTK_CONTAINER(hbox), combo);

	frame = gtk_frame_new("Options");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	box = gtk_vbox_new(FALSE, 10);
	gtk_container_add(GTK_CONTAINER(frame), box);

	hbox = gtk_hbox_new(TRUE, 4);
	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);

	button = gtk_check_button_new_with_label("Auto-spawn fio backend");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(button), 1);
	gtk_widget_set_tooltip_text(button, "When running fio locally, it is necessary to have the backend running on the same system. If this is checked, gfio will start the backend automatically for you if it isn't already running.");
	gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 6);

	gtk_widget_show_all(dialog);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return 1;
	}

	*host = strdup(gtk_entry_get_text(GTK_ENTRY(hentry)));
	*port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(pentry));

	typeentry = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo));
	if (!typeentry || !strncmp(typeentry, "IPv4", 4))
		*type = Fio_client_ipv4;
	else if (!strncmp(typeentry, "IPv6", 4))
		*type = Fio_client_ipv6;
	else
		*type = Fio_client_socket;
	g_free(typeentry);

	*server_start = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button));

	gtk_widget_destroy(dialog);
	return 0;
}

static void file_open(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog;
	GSList *filenames, *fn_glist;
	GtkFileFilter *filter;
	char *host;
	int port, type, server_start;

	dialog = gtk_file_chooser_dialog_new("Open File",
		GTK_WINDOW(ui.window),
		GTK_FILE_CHOOSER_ACTION_OPEN,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
		NULL);
	gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), TRUE);

	filter = gtk_file_filter_new();
	gtk_file_filter_add_pattern(filter, "*.fio");
	gtk_file_filter_add_pattern(filter, "*.job");
	gtk_file_filter_add_mime_type(filter, "text/fio");
	gtk_file_filter_set_name(filter, "Fio job file");
	gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(dialog), filter);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return;
	}

	fn_glist = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dialog));

	gtk_widget_destroy(dialog);

	if (get_connection_details(&host, &port, &type, &server_start))
		goto err;

	filenames = fn_glist;
	while (filenames != NULL) {
		ui.job_files = realloc(ui.job_files, (ui.nr_job_files + 1) * sizeof(char *));
		ui.job_files[ui.nr_job_files] = strdup(filenames->data);
		ui.nr_job_files++;

		ui.client = fio_client_add_explicit(host, type, port);
		if (!ui.client) {
			GError *error;

			error = g_error_new(g_quark_from_string("fio"), 1,
					"Failed to add client %s", host);
			report_error(error);
			g_error_free(error);
		}
		ui.client->client_data = &ui;
			
		g_free(filenames->data);
		filenames = g_slist_next(filenames);
	}
	free(host);
err:
	g_slist_free(fn_glist);
}

static void file_save(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog;

	dialog = gtk_file_chooser_dialog_new("Save File",
		GTK_WINDOW(ui.window),
		GTK_FILE_CHOOSER_ACTION_SAVE,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		GTK_STOCK_SAVE, GTK_RESPONSE_ACCEPT,
		NULL);

	gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(dialog), TRUE);
	gtk_file_chooser_set_current_name(GTK_FILE_CHOOSER(dialog), "Untitled document");

	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		char *filename;

		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		// save_job_file(filename);
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
}

static void preferences(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog, *frame, *box, **buttons;
	int i;

	dialog = gtk_dialog_new_with_buttons("Preferences",
		GTK_WINDOW(ui.window),
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
		GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
		NULL);

	frame = gtk_frame_new("Debug");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), frame, FALSE, FALSE, 5);
	box = gtk_hbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), box);

	buttons = malloc(sizeof(GtkWidget *) * FD_DEBUG_MAX);

	for (i = 0; i < FD_DEBUG_MAX; i++) {
		buttons[i] = gtk_check_button_new_with_label(debug_levels[i].name);
		gtk_box_pack_start(GTK_BOX(box), buttons[i], FALSE, FALSE, 6);
	}

	gtk_widget_show_all(dialog);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return;
	}

	for (i = 0; i < FD_DEBUG_MAX; i++) {
		int set;

		set = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(buttons[i]));
		if (set)
			fio_debug |= (1UL << i);
	}

	gtk_widget_destroy(dialog);
}

static void about_dialog(GtkWidget *w, gpointer data)
{
	gtk_show_about_dialog(NULL,
		"program-name", "gfio",
		"comments", "Gtk2 UI for fio",
		"license", "GPLv2",
		"version", fio_version_string,
		"copyright", "Jens Axboe <axboe@kernel.dk> 2012",
		"logo-icon-name", "fio",
		/* Must be last: */
		NULL, NULL,
		NULL);
}

static GtkActionEntry menu_items[] = {
	{ "FileMenuAction", GTK_STOCK_FILE, "File", NULL, NULL, NULL},
	{ "HelpMenuAction", GTK_STOCK_HELP, "Help", NULL, NULL, NULL},
	{ "OpenFile", GTK_STOCK_OPEN, NULL,   "<Control>O", NULL, G_CALLBACK(file_open) },
	{ "SaveFile", GTK_STOCK_SAVE, NULL,   "<Control>S", NULL, G_CALLBACK(file_save) },
	{ "Preferences", GTK_STOCK_PREFERENCES, NULL, "<Control>p", NULL, G_CALLBACK(preferences) },
	{ "Quit", GTK_STOCK_QUIT, NULL,   "<Control>Q", NULL, G_CALLBACK(quit_clicked) },
	{ "About", GTK_STOCK_ABOUT, NULL,  NULL, NULL, G_CALLBACK(about_dialog) },
};
static gint nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

static const gchar *ui_string = " \
	<ui> \
		<menubar name=\"MainMenu\"> \
			<menu name=\"FileMenu\" action=\"FileMenuAction\"> \
				<menuitem name=\"Open\" action=\"OpenFile\" /> \
				<menuitem name=\"Save\" action=\"SaveFile\" /> \
				<separator name=\"Separator\"/> \
				<menuitem name=\"Preferences\" action=\"Preferences\" /> \
				<separator name=\"Separator2\"/> \
				<menuitem name=\"Quit\" action=\"Quit\" /> \
			</menu> \
			<menu name=\"Help\" action=\"HelpMenuAction\"> \
				<menuitem name=\"About\" action=\"About\" /> \
			</menu> \
		</menubar> \
	</ui> \
";

static GtkWidget *get_menubar_menu(GtkWidget *window, GtkUIManager *ui_manager)
{
	GtkActionGroup *action_group = gtk_action_group_new("Menu");
	GError *error = 0;

	action_group = gtk_action_group_new("Menu");
	gtk_action_group_add_actions(action_group, menu_items, nmenu_items, 0);

	gtk_ui_manager_insert_action_group(ui_manager, action_group, 0);
	gtk_ui_manager_add_ui_from_string(GTK_UI_MANAGER(ui_manager), ui_string, -1, &error);

	gtk_window_add_accel_group(GTK_WINDOW(window), gtk_ui_manager_get_accel_group(ui_manager));
	return gtk_ui_manager_get_widget(ui_manager, "/MainMenu");
}

void gfio_ui_setup(GtkSettings *settings, GtkWidget *menubar,
                   GtkWidget *vbox, GtkUIManager *ui_manager)
{
        gtk_box_pack_start(GTK_BOX(vbox), menubar, FALSE, FALSE, 0);
}

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	GtkSettings *settings;
	GtkUIManager *uimanager;
	GtkWidget *menu, *probe, *probe_frame, *probe_box;

	memset(ui, 0, sizeof(*ui));

	/* Magical g*thread incantation, you just need this thread stuff.
	 * Without it, the update that happens in gfio_update_thread_status
	 * doesn't really happen in a timely fashion, you need expose events
	 */
	if (!g_thread_supported())
		g_thread_init(NULL);
	gdk_threads_init();

	gtk_init(argc, argv);
	settings = gtk_settings_get_default();
	gtk_settings_set_long_property(settings, "gtk_tooltip_timeout", 10, "gfio setting");
	g_type_init();
	
	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 700, 500);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK(quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK(quit_clicked), NULL);

	ui->vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (ui->window), ui->vbox);

	uimanager = gtk_ui_manager_new();
	menu = get_menubar_menu(ui->window, uimanager);
	gfio_ui_setup(settings, menu, ui->vbox, uimanager);

	/*
	 * Set up alignments for widgets at the top of ui, 
	 * align top left, expand horizontally but not vertically
	 */
	ui->topalign = gtk_alignment_new(0, 0, 1, 0);
	ui->topvbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(ui->topalign), ui->topvbox);
	gtk_box_pack_start(GTK_BOX(ui->vbox), ui->topalign, FALSE, FALSE, 0);

	probe = gtk_frame_new("Job");
	gtk_box_pack_start(GTK_BOX(ui->topvbox), probe, TRUE, FALSE, 3);
	probe_frame = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(probe), probe_frame);

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);
	ui->probe.hostname = new_info_label_in_frame(probe_box, "Host");
	ui->probe.os = new_info_label_in_frame(probe_box, "OS");
	ui->probe.arch = new_info_label_in_frame(probe_box, "Architecture");
	ui->probe.fio_ver = new_info_label_in_frame(probe_box, "Fio version");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);

	ui->eta.name = new_info_label_in_frame(probe_box, "Name");
	ui->eta.iotype = new_info_label_in_frame(probe_box, "IO");
	ui->eta.ioengine = new_info_label_in_frame(probe_box, "IO Engine");
	ui->eta.iodepth = new_info_label_in_frame(probe_box, "IO Depth");
	ui->eta.jobs = new_info_label_in_frame(probe_box, "Jobs");
	ui->eta.files = new_info_label_in_frame(probe_box, "Open files");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);
	ui->eta.read_bw = new_info_label_in_frame(probe_box, "Read BW");
	ui->eta.read_iops = new_info_label_in_frame(probe_box, "IOPS");
	ui->eta.write_bw = new_info_label_in_frame(probe_box, "Write BW");
	ui->eta.write_iops = new_info_label_in_frame(probe_box, "IOPS");

	/*
	 * Only add this if we have a commit rate
	 */
#if 0
	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);

	ui->eta.cr_bw = new_info_label_in_frame(probe_box, "Commit BW");
	ui->eta.cr_iops = new_info_label_in_frame(probe_box, "Commit IOPS");

	ui->eta.cw_bw = new_info_label_in_frame(probe_box, "Commit BW");
	ui->eta.cw_iops = new_info_label_in_frame(probe_box, "Commit IOPS");
#endif

	/*
	 * Add a text box for text op messages 
	 */
	ui->textview = gtk_text_view_new();
	ui->text = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ui->textview));
	gtk_text_buffer_set_text(ui->text, "", -1);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(ui->textview), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(ui->textview), FALSE);
	ui->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ui->scrolled_window),
					GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(ui->scrolled_window), ui->textview);
	gtk_box_pack_start(GTK_BOX(ui->vbox), ui->scrolled_window,
			TRUE, TRUE, 0);

	/*
	 * Set up alignments for widgets at the bottom of ui, 
	 * align bottom left, expand horizontally but not vertically
	 */
	ui->bottomalign = gtk_alignment_new(0, 1, 1, 0);
	ui->buttonbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ui->bottomalign), ui->buttonbox);
	gtk_box_pack_start(GTK_BOX(ui->vbox), ui->bottomalign,
					FALSE, FALSE, 0);

	add_buttons(ui, buttonspeclist, ARRAYSIZE(buttonspeclist));

	/*
	 * Set up thread status progress bar
	 */
	ui->thread_status_pb = gtk_progress_bar_new();
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui->thread_status_pb), 0.0);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui->thread_status_pb), "No connections");
	gtk_container_add(GTK_CONTAINER(ui->buttonbox), ui->thread_status_pb);


	gtk_widget_show_all(ui->window);
}

int main(int argc, char *argv[], char *envp[])
{
	if (initialize_fio(envp))
		return 1;
	if (fio_init_options())
		return 1;

	init_ui(&argc, &argv, &ui);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	return 0;
}
