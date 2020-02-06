#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <cairo.h>
#include <gtk/gtk.h>

#include "fio.h"
#include "gfio.h"
#include "ghelpers.h"
#include "goptions.h"
#include "gerror.h"
#include "graph.h"
#include "gclient.h"
#include "printing.h"
#include "lib/pow2.h"

static void gfio_display_ts(struct fio_client *client, struct thread_stat *ts,
			    struct group_run_stats *rs);

static gboolean results_window_delete(GtkWidget *w, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	gtk_widget_destroy(w);
	ge->results_window = NULL;
	ge->results_notebook = NULL;
	return TRUE;
}

static void results_close(GtkWidget *w, gpointer *data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	gtk_widget_destroy(ge->results_window);
}

static void results_print(GtkWidget *w, gpointer *data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	gfio_print_results(ge);
}

static GtkActionEntry results_menu_items[] = {
	{ "FileMenuAction", GTK_STOCK_FILE, "File", NULL, NULL, NULL},
	{ "GraphMenuAction", GTK_STOCK_FILE, "Graph", NULL, NULL, NULL},
	{ "PrintFile", GTK_STOCK_PRINT, "Print", "<Control>P", NULL, G_CALLBACK(results_print) },
	{ "CloseFile", GTK_STOCK_CLOSE, "Close", "<Control>W", NULL, G_CALLBACK(results_close) },
};
static gint results_nmenu_items = ARRAY_SIZE(results_menu_items);

static const gchar *results_ui_string = " \
	<ui> \
		<menubar name=\"MainMenu\"> \
			<menu name=\"FileMenu\" action=\"FileMenuAction\"> \
				<menuitem name=\"Print\" action=\"PrintFile\" /> \
				<menuitem name=\"Close\" action=\"CloseFile\" /> \
			</menu> \
			<menu name=\"GraphMenu\" action=\"GraphMenuAction\"> \
			</menu>\
		</menubar> \
	</ui> \
";

static GtkWidget *get_results_menubar(GtkWidget *window, struct gui_entry *ge)
{
	GtkActionGroup *action_group;
	GtkWidget *widget;
	GError *error = 0;

	ge->results_uimanager = gtk_ui_manager_new();

	action_group = gtk_action_group_new("ResultsMenu");
	gtk_action_group_add_actions(action_group, results_menu_items, results_nmenu_items, ge);

	gtk_ui_manager_insert_action_group(ge->results_uimanager, action_group, 0);
	gtk_ui_manager_add_ui_from_string(GTK_UI_MANAGER(ge->results_uimanager), results_ui_string, -1, &error);

	gtk_window_add_accel_group(GTK_WINDOW(window), gtk_ui_manager_get_accel_group(ge->results_uimanager));

	widget = gtk_ui_manager_get_widget(ge->results_uimanager, "/MainMenu");
	return widget;
}

static GtkWidget *get_results_window(struct gui_entry *ge)
{
	GtkWidget *win, *notebook, *vbox;

	if (ge->results_window)
		return ge->results_notebook;

	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "Results");
	gtk_window_set_default_size(GTK_WINDOW(win), 1024, 768);
	g_signal_connect(win, "delete-event", G_CALLBACK(results_window_delete), ge);
	g_signal_connect(win, "destroy", G_CALLBACK(results_window_delete), ge);

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(win), vbox);

	ge->results_menu = get_results_menubar(win, ge);
	gtk_box_pack_start(GTK_BOX(vbox), ge->results_menu, FALSE, FALSE, 0);

	notebook = gtk_notebook_new();
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), 1);
	gtk_notebook_popup_enable(GTK_NOTEBOOK(notebook));
	gtk_container_add(GTK_CONTAINER(vbox), notebook);

	ge->results_window = win;
	ge->results_notebook = notebook;
	return ge->results_notebook;
}

static void gfio_text_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_text_pdu *p = (struct cmd_text_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
	struct gui *ui = ge->ui;
	GtkTreeIter iter;
	struct tm *tm;
	time_t sec;
	char tmp[64], timebuf[96];

	sec = p->log_sec;
	tm = localtime(&sec);
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm);
	sprintf(timebuf, "%s.%03ld", tmp, (long) p->log_usec / 1000);

	gdk_threads_enter();

	gtk_list_store_append(ui->log_model, &iter);
	gtk_list_store_set(ui->log_model, &iter, 0, timebuf, -1);
	gtk_list_store_set(ui->log_model, &iter, 1, client->hostname, -1);
	gtk_list_store_set(ui->log_model, &iter, 2, log_get_level(p->level), -1);
	gtk_list_store_set(ui->log_model, &iter, 3, p->buf, -1);

	if (p->level == FIO_LOG_ERR)
		gfio_view_log(ui);

	gdk_threads_leave();
}

static void disk_util_destroy(GtkWidget *w, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	ge->disk_util_vbox = NULL;
	gtk_widget_destroy(w);
}

static GtkWidget *gfio_disk_util_get_vbox(struct gui_entry *ge)
{
	GtkWidget *vbox, *box, *scroll, *res_notebook;

	if (ge->disk_util_vbox)
		return ge->disk_util_vbox;

	scroll = get_scrolled_window(5);
	vbox = gtk_vbox_new(FALSE, 3);
	box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), vbox);
	res_notebook = get_results_window(ge);

	gtk_notebook_append_page(GTK_NOTEBOOK(res_notebook), scroll, gtk_label_new("Disk utilization"));
	ge->disk_util_vbox = box;
	g_signal_connect(vbox, "destroy", G_CALLBACK(disk_util_destroy), ge);

	return ge->disk_util_vbox;
}

static int __gfio_disk_util_show(GtkWidget *res_notebook,
				 struct gfio_client *gc, struct cmd_du_pdu *p)
{
	GtkWidget *box, *frame, *entry, *vbox, *util_vbox;
	struct gui_entry *ge = gc->ge;
	double util;
	char tmp[16];

	util_vbox = gfio_disk_util_get_vbox(ge);

	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(util_vbox), vbox);

	frame = gtk_frame_new((char *) p->dus.name);
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 2);

	box = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), box);

	frame = gtk_frame_new("Read");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IOs");
	entry_set_int_value(entry, p->dus.s.ios[0]);
	entry = new_info_entry_in_frame(vbox, "Merges");
	entry_set_int_value(entry, p->dus.s.merges[0]);
	entry = new_info_entry_in_frame(vbox, "Sectors");
	entry_set_int_value(entry, p->dus.s.sectors[0]);
	entry = new_info_entry_in_frame(vbox, "Ticks");
	entry_set_int_value(entry, p->dus.s.ticks[0]);

	frame = gtk_frame_new("Write");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IOs");
	entry_set_int_value(entry, p->dus.s.ios[1]);
	entry = new_info_entry_in_frame(vbox, "Merges");
	entry_set_int_value(entry, p->dus.s.merges[1]);
	entry = new_info_entry_in_frame(vbox, "Sectors");
	entry_set_int_value(entry, p->dus.s.sectors[1]);
	entry = new_info_entry_in_frame(vbox, "Ticks");
	entry_set_int_value(entry, p->dus.s.ticks[1]);

	frame = gtk_frame_new("Shared");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IO ticks");
	entry_set_int_value(entry, p->dus.s.io_ticks);
	entry = new_info_entry_in_frame(vbox, "Time in queue");
	entry_set_int_value(entry, p->dus.s.time_in_queue);

	util = 0.0;
	if (p->dus.s.msec)
		util = (double) 100 * p->dus.s.io_ticks / (double) p->dus.s.msec;
	if (util > 100.0)
		util = 100.0;

	sprintf(tmp, "%3.2f%%", util);
	entry = new_info_entry_in_frame(vbox, "Disk utilization");
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);

	gtk_widget_show_all(ge->results_window);
	return 0;
}

static int gfio_disk_util_show(struct gfio_client *gc)
{
	struct gui_entry *ge = gc->ge;
	GtkWidget *res_notebook;
	int i;

	if (!gc->nr_du)
		return 1;

	res_notebook = get_results_window(ge);

	for (i = 0; i < gc->nr_du; i++) {
		struct cmd_du_pdu *p = &gc->du[i];

		__gfio_disk_util_show(res_notebook, gc, p);
	}

	gtk_widget_show_all(ge->results_window);
	return 0;
}

static void gfio_disk_util_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_du_pdu *p = (struct cmd_du_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
	unsigned int nr = gc->nr_du;

	gc->du = realloc(gc->du, (nr + 1) * sizeof(struct cmd_du_pdu));
	memcpy(&gc->du[nr], p, sizeof(*p));
	gc->nr_du++;

	gdk_threads_enter();
	if (ge->results_window)
		__gfio_disk_util_show(ge->results_notebook, gc, p);
	else
		gfio_disk_util_show(gc);
	gdk_threads_leave();
}

static int sum_stat_nr;

static void gfio_thread_status_op(struct fio_client *client,
				  struct fio_net_cmd *cmd)
{
	struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;

	gfio_display_ts(client, &p->ts, &p->rs);

	if (sum_stat_clients == 1)
		return;

	sum_thread_stats(&client_ts, &p->ts, sum_stat_nr == 1);
	sum_group_stats(&client_gs, &p->rs);

	client_ts.members++;
	client_ts.thread_number = p->ts.thread_number;
	client_ts.groupid = p->ts.groupid;
	client_ts.sig_figs = p->ts.sig_figs;

	if (++sum_stat_nr == sum_stat_clients) {
		strcpy(client_ts.name, "All clients");
		gfio_display_ts(client, &client_ts, &client_gs);
	}
}

static void gfio_group_stats_op(struct fio_client *client,
				struct fio_net_cmd *cmd)
{
	/* We're ignoring group stats for now */
}

static void gfio_update_thread_status(struct gui_entry *ge,
				      char *status_message, double perc)
{
	static char message[100];
	const char *m = message;

	snprintf(message, sizeof(message), "%s", status_message);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ge->thread_status_pb), m);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ge->thread_status_pb), perc / 100.0);
	gtk_widget_queue_draw(ge->ui->window);
}

static void gfio_update_thread_status_all(struct gui *ui, char *status_message,
					  double perc)
{
	static char message[100];
	const char *m = message;

	snprintf(message, sizeof(message), "%s", status_message);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui->thread_status_pb), m);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui->thread_status_pb), perc / 100.0);
	gtk_widget_queue_draw(ui->window);
}

/*
 * Client specific ETA
 */
static void gfio_update_client_eta(struct fio_client *client, struct jobs_eta *je)
{
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
	static int eta_good;
	char eta_str[128];
	char output[256];
	char tmp[32];
	double perc = 0.0;
	int i2p = 0;

	gdk_threads_enter();

	eta_str[0] = '\0';
	output[0] = '\0';

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	sprintf(tmp, "%u", je->nr_running);
	gtk_entry_set_text(GTK_ENTRY(ge->eta.jobs), tmp);
	sprintf(tmp, "%u", je->files_open);
	gtk_entry_set_text(GTK_ENTRY(ge->eta.files), tmp);

	if (je->eta_sec != INT_MAX && je->nr_running) {
		char *iops_str[DDIR_RWDIR_CNT];
		char *rate_str[DDIR_RWDIR_CNT];
		char *rate_alt[DDIR_RWDIR_CNT];
		char tmp[128];
		int i;

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running)
			strcpy(output, "-.-% done");
		else {
			eta_good = 1;
			perc *= 100.0;
			sprintf(output, "%3.1f%% done", perc);
		}

		iops_str[0] = num2str(je->iops[0], je->sig_figs, 1, 0, N2S_PERSEC);
		iops_str[1] = num2str(je->iops[1], je->sig_figs, 1, 0, N2S_PERSEC);
		iops_str[2] = num2str(je->iops[2], je->sig_figs, 1, 0, N2S_PERSEC);

		rate_str[0] = num2str(je->rate[0], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[0] = num2str(je->rate[0], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[0], rate_alt[0]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.read_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.read_iops), iops_str[0]);

		rate_str[1] = num2str(je->rate[1], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[1] = num2str(je->rate[1], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[1], rate_alt[1]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.write_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.write_iops), iops_str[1]);

		rate_str[2] = num2str(je->rate[2], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[2] = num2str(je->rate[2], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[2], rate_alt[2]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.trim_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.trim_iops), iops_str[2]);

		graph_add_xy_data(ge->graphs.iops_graph, ge->graphs.read_iops, je->elapsed_sec, je->iops[0], iops_str[0]);
		graph_add_xy_data(ge->graphs.iops_graph, ge->graphs.write_iops, je->elapsed_sec, je->iops[1], iops_str[1]);
		graph_add_xy_data(ge->graphs.iops_graph, ge->graphs.trim_iops, je->elapsed_sec, je->iops[2], iops_str[2]);
		graph_add_xy_data(ge->graphs.bandwidth_graph, ge->graphs.read_bw, je->elapsed_sec, je->rate[0], rate_str[0]);
		graph_add_xy_data(ge->graphs.bandwidth_graph, ge->graphs.write_bw, je->elapsed_sec, je->rate[1], rate_str[1]);
		graph_add_xy_data(ge->graphs.bandwidth_graph, ge->graphs.trim_bw, je->elapsed_sec, je->rate[2], rate_str[2]);

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			free(rate_str[i]);
			free(rate_alt[i]);
			free(iops_str[i]);
		}
	}

	if (eta_str[0]) {
		char *dst = output + strlen(output);

		sprintf(dst, " - %s", eta_str);
	}

	gfio_update_thread_status(ge, output, perc);
	gdk_threads_leave();
}

/*
 * Update ETA in main window for all clients
 */
static void gfio_update_all_eta(struct jobs_eta *je)
{
	struct gui *ui = &main_ui;
	static int eta_good;
	char eta_str[128];
	char output[256];
	double perc = 0.0;
	int i, i2p = 0;

	gdk_threads_enter();

	eta_str[0] = '\0';
	output[0] = '\0';

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

	entry_set_int_value(ui->eta.jobs, je->nr_running);

	if (je->eta_sec != INT_MAX && je->nr_running) {
		char *iops_str[DDIR_RWDIR_CNT];
		char *rate_str[DDIR_RWDIR_CNT];
		char *rate_alt[DDIR_RWDIR_CNT];
		char tmp[128];

		if ((!je->eta_sec && !eta_good) || je->nr_ramp == je->nr_running)
			strcpy(output, "-.-% done");
		else {
			eta_good = 1;
			perc *= 100.0;
			sprintf(output, "%3.1f%% done", perc);
		}

		iops_str[0] = num2str(je->iops[0], je->sig_figs, 1, 0, N2S_PERSEC);
		iops_str[1] = num2str(je->iops[1], je->sig_figs, 1, 0, N2S_PERSEC);
		iops_str[2] = num2str(je->iops[2], je->sig_figs, 1, 0, N2S_PERSEC);

		rate_str[0] = num2str(je->rate[0], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[0] = num2str(je->rate[0], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[0], rate_alt[0]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.read_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.read_iops), iops_str[0]);

		rate_str[1] = num2str(je->rate[1], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[1] = num2str(je->rate[1], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[1], rate_alt[1]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.write_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.write_iops), iops_str[1]);

		rate_str[2] = num2str(je->rate[2], je->sig_figs, 10, i2p, N2S_BYTEPERSEC);
		rate_alt[2] = num2str(je->rate[2], je->sig_figs, 10, !i2p, N2S_BYTEPERSEC);
		snprintf(tmp, sizeof(tmp), "%s (%s)", rate_str[2], rate_alt[2]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.trim_bw), tmp);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.trim_iops), iops_str[2]);

		graph_add_xy_data(ui->graphs.iops_graph, ui->graphs.read_iops, je->elapsed_sec, je->iops[0], iops_str[0]);
		graph_add_xy_data(ui->graphs.iops_graph, ui->graphs.write_iops, je->elapsed_sec, je->iops[1], iops_str[1]);
		graph_add_xy_data(ui->graphs.iops_graph, ui->graphs.trim_iops, je->elapsed_sec, je->iops[2], iops_str[2]);
		graph_add_xy_data(ui->graphs.bandwidth_graph, ui->graphs.read_bw, je->elapsed_sec, je->rate[0], rate_str[0]);
		graph_add_xy_data(ui->graphs.bandwidth_graph, ui->graphs.write_bw, je->elapsed_sec, je->rate[1], rate_str[1]);
		graph_add_xy_data(ui->graphs.bandwidth_graph, ui->graphs.trim_bw, je->elapsed_sec, je->rate[2], rate_str[2]);

		for (i = 0; i < DDIR_RWDIR_CNT; i++) {
			free(rate_str[i]);
			free(rate_alt[i]);
			free(iops_str[i]);
		}
	}

	if (eta_str[0]) {
		char *dst = output + strlen(output);

		sprintf(dst, " - %s", eta_str);
	}

	gfio_update_thread_status_all(ui, output, perc);
	gdk_threads_leave();
}

static void gfio_probe_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_reply_pdu *probe = (struct cmd_probe_reply_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
	const char *os, *arch;

	os = fio_get_os_string(probe->os);
	if (!os)
		os = "unknown";

	arch = fio_get_arch_string(probe->arch);
	if (!arch)
		os = "unknown";

	if (!client->name)
		client->name = strdup((char *) probe->hostname);

	gc->client_cpus = le32_to_cpu(probe->cpus);
	gc->client_flags = le64_to_cpu(probe->flags);

	gdk_threads_enter();

	gtk_label_set_text(GTK_LABEL(ge->probe.hostname), (char *) probe->hostname);
	gtk_label_set_text(GTK_LABEL(ge->probe.os), os);
	gtk_label_set_text(GTK_LABEL(ge->probe.arch), arch);
	gtk_label_set_text(GTK_LABEL(ge->probe.fio_ver), (char *) probe->fio_version);

	gfio_set_state(ge, GE_STATE_CONNECTED);

	gdk_threads_leave();
}

static void gfio_quit_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();
	gfio_set_state(gc->ge, GE_STATE_NEW);
	gdk_threads_leave();
}

static struct thread_options *gfio_client_add_job(struct gfio_client *gc,
			struct thread_options_pack *top)
{
	struct gfio_client_options *gco;

	gco = calloc(1, sizeof(*gco));
	convert_thread_options_to_cpu(&gco->o, top);
	INIT_FLIST_HEAD(&gco->list);
	flist_add_tail(&gco->list, &gc->o_list);
	gc->o_list_nr = 1;
	return &gco->o;
}

static void gfio_add_job_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_add_job_pdu *p = (struct cmd_add_job_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
	struct thread_options *o;
	char *c1, *c2, *c3, *c4;
	char tmp[80];
	int i2p;

	p->thread_number = le32_to_cpu(p->thread_number);
	p->groupid = le32_to_cpu(p->groupid);
	o = gfio_client_add_job(gc, &p->top);

	gdk_threads_enter();

	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(ge->eta.names), (gchar *) o->name);
	gtk_combo_box_set_active(GTK_COMBO_BOX(ge->eta.names), 0);

	sprintf(tmp, "%s %s", o->odirect ? "direct" : "buffered", ddir_str(o->td_ddir));
	multitext_add_entry(&ge->eta.iotype, tmp);

	i2p = is_power_of_2(o->kb_base);
	c1 = num2str(o->min_bs[DDIR_READ], o->sig_figs, 1, i2p, N2S_BYTE);
	c2 = num2str(o->max_bs[DDIR_READ], o->sig_figs, 1, i2p, N2S_BYTE);
	c3 = num2str(o->min_bs[DDIR_WRITE], o->sig_figs, 1, i2p, N2S_BYTE);
	c4 = num2str(o->max_bs[DDIR_WRITE], o->sig_figs, 1, i2p, N2S_BYTE);

	sprintf(tmp, "%s-%s,%s-%s", c1, c2, c3, c4);
	free(c1);
	free(c2);
	free(c3);
	free(c4);
	multitext_add_entry(&ge->eta.bs, tmp);

	multitext_add_entry(&ge->eta.ioengine, (const char *) o->ioengine);

	sprintf(tmp, "%u", o->iodepth);
	multitext_add_entry(&ge->eta.iodepth, tmp);

	multitext_set_entry(&ge->eta.iotype, 0);
	multitext_set_entry(&ge->eta.bs, 0);
	multitext_set_entry(&ge->eta.ioengine, 0);
	multitext_set_entry(&ge->eta.iodepth, 0);

	gfio_set_state(ge, GE_STATE_JOB_SENT);

	gdk_threads_leave();
}

static void gfio_update_job_op(struct fio_client *client,
			       struct fio_net_cmd *cmd)
{
	uint32_t *pdu_error = (uint32_t *) cmd->payload;
	struct gfio_client *gc = client->client_data;

	gc->update_job_status = le32_to_cpu(*pdu_error);
	gc->update_job_done = 1;
}

static void gfio_client_timed_out(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;
	char buf[256];

	gdk_threads_enter();

	gfio_set_state(gc->ge, GE_STATE_NEW);
	clear_ge_ui_info(gc->ge);

	sprintf(buf, "Client %s: timeout talking to server.\n", client->hostname);
	gfio_report_info(gc->ge->ui, "Network timeout", buf);

	gdk_threads_leave();
}

static void gfio_client_stop(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();

	gfio_set_state(gc->ge, GE_STATE_JOB_DONE);

	if (gc->err_entry)
		entry_set_int_value(gc->err_entry, client->error);

	gdk_threads_leave();
}

static void gfio_client_start(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();
	gfio_set_state(gc->ge, GE_STATE_JOB_STARTED);
	gdk_threads_leave();
}

static void gfio_client_job_start(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();
	gfio_set_state(gc->ge, GE_STATE_JOB_RUNNING);
	gdk_threads_leave();
}

static void gfio_add_total_depths_tree(GtkListStore *model,
				       struct thread_stat *ts, unsigned int len)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	GtkTreeIter iter;
	/* Bits 1-6, and 8 */
	const int add_mask = 0x17e;
	int i, j;

	stat_calc_dist(ts->io_u_map, ddir_rw_sum(ts->total_io_u), io_u_dist);

	gtk_list_store_append(model, &iter);

	gtk_list_store_set(model, &iter, 0, "Total", -1);

	for (i = 1, j = 0; i < len; i++) {
		char fbuf[32];

		if (!(add_mask & (1UL << (i - 1))))
			sprintf(fbuf, "0.0%%");
		else {
			sprintf(fbuf, "%3.1f%%", io_u_dist[j]);
			j++;
		}

		gtk_list_store_set(model, &iter, i, fbuf, -1);
	}

}

static void gfio_add_end_results(struct gfio_client *gc, struct thread_stat *ts,
				 struct group_run_stats *rs)
{
	unsigned int nr = gc->nr_results;

	gc->results = realloc(gc->results, (nr + 1) * sizeof(struct end_results));
	memcpy(&gc->results[nr].ts, ts, sizeof(*ts));
	memcpy(&gc->results[nr].gs, rs, sizeof(*rs));
	gc->nr_results++;
}

static void gfio_add_sc_depths_tree(GtkListStore *model,
				    struct thread_stat *ts, unsigned int len,
				    int submit)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	GtkTreeIter iter;
	/* Bits 0, and 3-8 */
	const int add_mask = 0x1f9;
	int i, j;

	if (submit)
		stat_calc_dist(ts->io_u_submit, ts->total_submit, io_u_dist);
	else
		stat_calc_dist(ts->io_u_complete, ts->total_complete, io_u_dist);

	gtk_list_store_append(model, &iter);

	gtk_list_store_set(model, &iter, 0, submit ? "Submit" : "Complete", -1);

	for (i = 1, j = 0; i < len; i++) {
		char fbuf[32];

		if (!(add_mask & (1UL << (i - 1))))
			sprintf(fbuf, "0.0%%");
		else {
			sprintf(fbuf, "%3.1f%%", io_u_dist[j]);
			j++;
		}

		gtk_list_store_set(model, &iter, i, fbuf, -1);
	}

}

static void gfio_show_io_depths(GtkWidget *vbox, struct thread_stat *ts)
{
	GtkWidget *frame, *box, *tree_view = NULL;
	GtkTreeSelection *selection;
	GtkListStore *model;
	int i;
	const char *labels[] = { "Depth", "0", "1", "2", "4", "8", "16", "32", "64", ">= 64" };
	const int nr_labels = ARRAY_SIZE(labels);
	GType types[nr_labels];

	frame = gtk_frame_new("IO depths");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	box = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), box);

	for (i = 0; i < nr_labels; i++)
		types[i] = G_TYPE_STRING;

	model = gtk_list_store_newv(nr_labels, types);

	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(model));
	gtk_widget_set_can_focus(tree_view, FALSE);

	g_object_set(G_OBJECT(tree_view), "headers-visible", TRUE,
		"enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_BOTH, NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(GTK_TREE_SELECTION(selection), GTK_SELECTION_BROWSE);

	for (i = 0; i < nr_labels; i++)
		tree_view_column(tree_view, i, labels[i], ALIGN_RIGHT | UNSORTABLE);

	gfio_add_total_depths_tree(model, ts, nr_labels);
	gfio_add_sc_depths_tree(model, ts, nr_labels, 1);
	gfio_add_sc_depths_tree(model, ts, nr_labels, 0);

	gtk_box_pack_start(GTK_BOX(box), tree_view, TRUE, TRUE, 3);
}

static void gfio_show_cpu_usage(GtkWidget *vbox, struct thread_stat *ts)
{
	GtkWidget *box, *frame, *entry;
	double usr_cpu, sys_cpu;
	unsigned long runtime;
	char tmp[32];

	runtime = ts->total_run_time;
	if (runtime) {
		double runt = (double) runtime;

		usr_cpu = (double) ts->usr_time * 100 / runt;
		sys_cpu = (double) ts->sys_time * 100 / runt;
	} else {
		usr_cpu = 0;
		sys_cpu = 0;
	}

	frame = gtk_frame_new("OS resources");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	box = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), box);

	entry = new_info_entry_in_frame(box, "User CPU");
	sprintf(tmp, "%3.2f%%", usr_cpu);
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);
	entry = new_info_entry_in_frame(box, "System CPU");
	sprintf(tmp, "%3.2f%%", sys_cpu);
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);
	entry = new_info_entry_in_frame(box, "Context switches");
	entry_set_int_value(entry, ts->ctx);
	entry = new_info_entry_in_frame(box, "Major faults");
	entry_set_int_value(entry, ts->majf);
	entry = new_info_entry_in_frame(box, "Minor faults");
	entry_set_int_value(entry, ts->minf);
}

static GtkWidget *gfio_output_lat_buckets(double *lat, const char **labels,
					  int num)
{
	GtkWidget *tree_view;
	GtkTreeSelection *selection;
	GtkListStore *model;
	GtkTreeIter iter;
	GType *types;
	int i;

	types = malloc(num * sizeof(GType));

	for (i = 0; i < num; i++)
		types[i] = G_TYPE_STRING;

	model = gtk_list_store_newv(num, types);
	free(types);
	types = NULL;

	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(model));
	gtk_widget_set_can_focus(tree_view, FALSE);

	g_object_set(G_OBJECT(tree_view), "headers-visible", TRUE,
		"enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_BOTH, NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(GTK_TREE_SELECTION(selection), GTK_SELECTION_BROWSE);

	for (i = 0; i < num; i++)
		tree_view_column(tree_view, i, labels[i], ALIGN_RIGHT | UNSORTABLE);

	gtk_list_store_append(model, &iter);

	for (i = 0; i < num; i++) {
		char fbuf[32];

		if (lat[i] <= 0.0)
			sprintf(fbuf, "0.00");
		else
			sprintf(fbuf, "%3.2f%%", lat[i]);

		gtk_list_store_set(model, &iter, i, fbuf, -1);
	}

	return tree_view;
}

static struct graph *setup_lat_bucket_graph(const char *title, double *lat,
					    const char **labels,
					    unsigned int len,
					    double xdim, double ydim)
{
	struct graph *g;
	int i;

	g = graph_new(xdim, ydim, gfio_graph_font);
	graph_title(g, title);
	graph_x_title(g, "Buckets");
	graph_y_title(g, "Percent");

	for (i = 0; i < len; i++) {
		graph_label_t l;

		l = graph_add_label(g, labels[i]);
		graph_add_data(g, l, lat[i]);
	}

	return g;
}

static int on_expose_lat_drawing_area(GtkWidget *w, GdkEvent *event, gpointer p)
{
	struct graph *g = p;
	cairo_t *cr;

	cr = gdk_cairo_create(gtk_widget_get_window(w));
#if 0
	if (graph_has_tooltips(g)) {
		g_object_set(w, "has-tooltip", TRUE, NULL);
		g_signal_connect(w, "query-tooltip", G_CALLBACK(clat_graph_tooltip), g);
	}
#endif
	cairo_set_source_rgb(cr, 0, 0, 0);
	bar_graph_draw(g, cr);
	cairo_destroy(cr);

	return FALSE;
}

static gint on_config_lat_drawing_area(GtkWidget *w, GdkEventConfigure *event,
				       gpointer data)
{
	guint width = gtk_widget_get_allocated_width(w);
	guint height = gtk_widget_get_allocated_height(w);
	struct graph *g = data;

	graph_set_size(g, width, height);
	graph_set_size(g, width, height);
	graph_set_position(g, 0, 0);
	return TRUE;
}

static void gfio_show_latency_buckets(struct gfio_client *gc, GtkWidget *vbox,
				      struct thread_stat *ts)
{
	double io_u_lat[FIO_IO_U_LAT_N_NR + FIO_IO_U_LAT_U_NR + FIO_IO_U_LAT_M_NR];
	const char *ranges[] = { "2ns", "4ns", "10ns", "20ns", "50ns", "100ns",
				 "250ns", "500ns", "750ns", "1000ns", "2us",
				 "4us", "10us", "20us", "50us", "100us",
				 "250us", "500us", "750us", "1ms", "2ms",
				 "4ms", "10ms", "20ms", "50ms", "100ms",
				 "250ms", "500ms", "750ms", "1s", "2s", ">= 2s" };
	int start, end, i;
	const int total = FIO_IO_U_LAT_U_NR + FIO_IO_U_LAT_M_NR;
	GtkWidget *frame, *tree_view, *hbox, *completion_vbox, *drawing_area;
	struct gui_entry *ge = gc->ge;

	stat_calc_lat_n(ts, io_u_lat);
	stat_calc_lat_u(ts, &io_u_lat[FIO_IO_U_LAT_N_NR]);
	stat_calc_lat_m(ts, &io_u_lat[FIO_IO_U_LAT_N_NR + FIO_IO_U_LAT_U_NR]);

	/*
	 * Found out which first bucket has entries, and which last bucket
	 */
	start = end = -1U;
	for (i = 0; i < total; i++) {
		if (io_u_lat[i] == 0.00)
			continue;

		if (start == -1U)
			start = i;
		end = i;
	}

	/*
	 * No entries...
	 */
	if (start == -1U)
		return;

	tree_view = gfio_output_lat_buckets(&io_u_lat[start], &ranges[start], end - start + 1);
	ge->lat_bucket_graph = setup_lat_bucket_graph("Latency buckets", &io_u_lat[start], &ranges[start], end - start + 1, 700.0, 300.0);

	frame = gtk_frame_new("Latency buckets");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	completion_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), completion_vbox);
	hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(completion_vbox), hbox);

	drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(drawing_area), 700, 300);
	gtk_widget_modify_bg(drawing_area, GTK_STATE_NORMAL, &gfio_color_white);
	gtk_container_add(GTK_CONTAINER(completion_vbox), drawing_area);
	g_signal_connect(G_OBJECT(drawing_area), GFIO_DRAW_EVENT, G_CALLBACK(on_expose_lat_drawing_area), ge->lat_bucket_graph);
	g_signal_connect(G_OBJECT(drawing_area), "configure_event", G_CALLBACK(on_config_lat_drawing_area), ge->lat_bucket_graph);

	gtk_box_pack_start(GTK_BOX(hbox), tree_view, TRUE, TRUE, 3);
}

static void gfio_show_lat(GtkWidget *vbox, const char *name, unsigned long long min,
			  unsigned long long max, double mean, double dev)
{
	const char *base = "(nsec)";
	GtkWidget *hbox, *label, *frame;
	char *minp, *maxp;
	char tmp[64];

	if (nsec_to_msec(&min, &max, &mean, &dev))
		base = "(msec)";
	else if (nsec_to_usec(&min, &max, &mean, &dev))
		base = "(usec)";

	minp = num2str(min, 6, 1, 0, N2S_NONE);
	maxp = num2str(max, 6, 1, 0, N2S_NONE);

	sprintf(tmp, "%s %s", name, base);
	frame = gtk_frame_new(tmp);
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), hbox);

	label = new_info_label_in_frame(hbox, "Minimum");
	gtk_label_set_text(GTK_LABEL(label), minp);
	label = new_info_label_in_frame(hbox, "Maximum");
	gtk_label_set_text(GTK_LABEL(label), maxp);
	label = new_info_label_in_frame(hbox, "Average");
	sprintf(tmp, "%5.02f", mean);
	gtk_label_set_text(GTK_LABEL(label), tmp);
	label = new_info_label_in_frame(hbox, "Standard deviation");
	sprintf(tmp, "%5.02f", dev);
	gtk_label_set_text(GTK_LABEL(label), tmp);

	free(minp);
	free(maxp);
}

static GtkWidget *gfio_output_clat_percentiles(unsigned long long *ovals,
					       fio_fp64_t *plist,
					       unsigned int len,
					       const char *base,
					       unsigned int scale)
{
	GType types[FIO_IO_U_LIST_MAX_LEN];
	GtkWidget *tree_view;
	GtkTreeSelection *selection;
	GtkListStore *model;
	GtkTreeIter iter;
	int i, j;

	for (i = 0; i < len; i++)
		types[i] = G_TYPE_ULONG;

	model = gtk_list_store_newv(len, types);

	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(model));
	gtk_widget_set_can_focus(tree_view, FALSE);

	g_object_set(G_OBJECT(tree_view), "headers-visible", TRUE,
		"enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_BOTH, NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(GTK_TREE_SELECTION(selection), GTK_SELECTION_BROWSE);

	for (i = 0; i < len; i++) {
		char fbuf[8];

		sprintf(fbuf, "%2.2f%%", plist[i].u.f);
		tree_view_column(tree_view, i, fbuf, ALIGN_RIGHT | UNSORTABLE);
	}

	gtk_list_store_append(model, &iter);

	for (i = 0; i < len; i++) {
		for (j = 0; j < scale; j++)
			ovals[i] = (ovals[i] + 999) / 1000;
		gtk_list_store_set(model, &iter, i, (unsigned long) ovals[i], -1);
	}

	return tree_view;
}

static struct graph *setup_clat_graph(char *title, unsigned long long *ovals,
				      fio_fp64_t *plist,
				      unsigned int len,
				      double xdim, double ydim)
{
	struct graph *g;
	int i;

	g = graph_new(xdim, ydim, gfio_graph_font);
	graph_title(g, title);
	graph_x_title(g, "Percentile");
	graph_y_title(g, "Time");

	for (i = 0; i < len; i++) {
		graph_label_t l;
		char fbuf[8];

		sprintf(fbuf, "%2.2f%%", plist[i].u.f);
		l = graph_add_label(g, fbuf);
		graph_add_data(g, l, (double) ovals[i]);
	}

	return g;
}

static void gfio_show_clat_percentiles(struct gfio_client *gc,
				       GtkWidget *vbox, struct thread_stat *ts,
				       int ddir, uint64_t *io_u_plat,
				       unsigned long long nr, const char *type)
{
	fio_fp64_t *plist = ts->percentile_list;
	unsigned int len, scale_down;
	unsigned long long *ovals, minv, maxv;
	const char *base;
	GtkWidget *tree_view, *frame, *hbox, *drawing_area, *completion_vbox;
	struct gui_entry *ge = gc->ge;
	char tmp[64];

	len = calc_clat_percentiles(io_u_plat, nr, plist, &ovals, &maxv, &minv);
	if (!len)
		goto out;

	/*
	 * We default to nsecs, but if the value range is such that we
	 * should scale down to usecs or msecs, do that.
	 */
        if (minv > 2000000 && maxv > 99999999ULL) {
                scale_down = 2;
		base = "msec";
        } else if (minv > 2000 && maxv > 99999) {
                scale_down = 1;
		base = "usec";
        } else {
                scale_down = 0;
		base = "nsec";
        }

	sprintf(tmp, "%s latency percentiles (%s)", type, base);

	tree_view = gfio_output_clat_percentiles(ovals, plist, len, base, scale_down);
	ge->clat_graph = setup_clat_graph(tmp, ovals, plist, len, 700.0, 300.0);

	frame = gtk_frame_new(tmp);
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	completion_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), completion_vbox);
	hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(completion_vbox), hbox);
	drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(drawing_area), 700, 300);
	gtk_widget_modify_bg(drawing_area, GTK_STATE_NORMAL, &gfio_color_white);
	gtk_container_add(GTK_CONTAINER(completion_vbox), drawing_area);
	g_signal_connect(G_OBJECT(drawing_area), GFIO_DRAW_EVENT, G_CALLBACK(on_expose_lat_drawing_area), ge->clat_graph);
	g_signal_connect(G_OBJECT(drawing_area), "configure_event", G_CALLBACK(on_config_lat_drawing_area), ge->clat_graph);

	gtk_box_pack_start(GTK_BOX(hbox), tree_view, TRUE, TRUE, 3);
out:
	if (ovals)
		free(ovals);
}

#define GFIO_CLAT	1
#define GFIO_SLAT	2
#define GFIO_LAT	4
#define GFIO_HILAT	8
#define GFIO_LOLAT	16

static void gfio_show_ddir_status(struct gfio_client *gc, GtkWidget *mbox,
				  struct group_run_stats *rs,
				  struct thread_stat *ts, int ddir)
{
	const char *ddir_label[3] = { "Read", "Write", "Trim" };
	const char *hilat, *lolat;
	GtkWidget *frame, *label, *box, *vbox, *main_vbox;
	unsigned long long min[5], max[5];
	unsigned long runt;
	unsigned long long bw, iops;
	unsigned int flags = 0;
	double mean[5], dev[5];
	char *io_p, *io_palt, *bw_p, *bw_palt, *iops_p;
	char tmp[128];
	int i2p;

	if (!ts->runtime[ddir])
		return;

	i2p = is_power_of_2(rs->kb_base);
	runt = ts->runtime[ddir];

	bw = (1000 * ts->io_bytes[ddir]) / runt;

	iops = (1000 * (uint64_t)ts->total_io_u[ddir]) / runt;
	iops_p = num2str(iops, ts->sig_figs, 1, 0, N2S_PERSEC);

	box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(mbox), box, TRUE, FALSE, 3);

	frame = gtk_frame_new(ddir_label[ddir]);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 5);

	main_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), main_vbox);

	box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(main_vbox), box, TRUE, FALSE, 3);

	label = new_info_label_in_frame(box, "IO");
	io_p = num2str(ts->io_bytes[ddir], ts->sig_figs, 1, i2p, N2S_BYTE);
	io_palt = num2str(ts->io_bytes[ddir], ts->sig_figs, 1, !i2p, N2S_BYTE);
	snprintf(tmp, sizeof(tmp), "%s (%s)", io_p, io_palt);
	gtk_label_set_text(GTK_LABEL(label), tmp);

	label = new_info_label_in_frame(box, "Bandwidth");
	bw_p = num2str(bw, ts->sig_figs, 1, i2p, ts->unit_base);
	bw_palt = num2str(bw, ts->sig_figs, 1, !i2p, ts->unit_base);
	snprintf(tmp, sizeof(tmp), "%s (%s)", bw_p, bw_palt);
	gtk_label_set_text(GTK_LABEL(label), tmp);

	label = new_info_label_in_frame(box, "IOPS");
	gtk_label_set_text(GTK_LABEL(label), iops_p);
	label = new_info_label_in_frame(box, "Runtime (msec)");
	label_set_int_value(label, ts->runtime[ddir]);

	if (calc_lat(&ts->bw_stat[ddir], &min[0], &max[0], &mean[0], &dev[0])) {
		double p_of_agg = 100.0;
		const char *bw_str = "KiB/s";
		char tmp[32];

		if (rs->agg[ddir]) {
			p_of_agg = mean[0] * 100 / (double) rs->agg[ddir];
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}

		if (mean[0] > 1073741824.9) {
			min[0] /= 1048576.0;
			max[0] /= 1048576.0;
			mean[0] /= 1048576.0;
			dev[0] /= 1048576.0;
			bw_str = "GiB/s";
		}

		if (mean[0] > 1047575.9) {
			min[0] /= 1024.0;
			max[0] /= 1024.0;
			mean[0] /= 1024.0;
			dev[0] /= 1024.0;
			bw_str = "MiB/s";
		}
		sprintf(tmp, "Bandwidth (%s)", bw_str);
		frame = gtk_frame_new(tmp);
		gtk_box_pack_start(GTK_BOX(main_vbox), frame, FALSE, FALSE, 5);

		box = gtk_hbox_new(FALSE, 3);
		gtk_container_add(GTK_CONTAINER(frame), box);

		label = new_info_label_in_frame(box, "Minimum");
		label_set_int_value(label, min[0]);
		label = new_info_label_in_frame(box, "Maximum");
		label_set_int_value(label, max[0]);
		label = new_info_label_in_frame(box, "Percentage of jobs");
		sprintf(tmp, "%3.2f%%", p_of_agg);
		gtk_label_set_text(GTK_LABEL(label), tmp);
		label = new_info_label_in_frame(box, "Average");
		sprintf(tmp, "%5.02f", mean[0]);
		gtk_label_set_text(GTK_LABEL(label), tmp);
		label = new_info_label_in_frame(box, "Standard deviation");
		sprintf(tmp, "%5.02f", dev[0]);
		gtk_label_set_text(GTK_LABEL(label), tmp);
	}

	if (calc_lat(&ts->slat_stat[ddir], &min[0], &max[0], &mean[0], &dev[0]))
		flags |= GFIO_SLAT;
	if (calc_lat(&ts->clat_stat[ddir], &min[1], &max[1], &mean[1], &dev[1]))
		flags |= GFIO_CLAT;
	if (calc_lat(&ts->lat_stat[ddir], &min[2], &max[2], &mean[2], &dev[2]))
		flags |= GFIO_LAT;
	if (calc_lat(&ts->clat_high_prio_stat[ddir], &min[3], &max[3], &mean[3], &dev[3])) {
		flags |= GFIO_HILAT;
		if (calc_lat(&ts->clat_low_prio_stat[ddir], &min[4], &max[4], &mean[4], &dev[4]))
			flags |= GFIO_LOLAT;
		/* we only want to print low priority statistics if other IOs were
		 * submitted with the priority bit set
		 */
	}

	if (flags) {
		frame = gtk_frame_new("Latency");
		gtk_box_pack_start(GTK_BOX(main_vbox), frame, FALSE, FALSE, 5);

		vbox = gtk_vbox_new(FALSE, 3);
		gtk_container_add(GTK_CONTAINER(frame), vbox);

		if (ts->lat_percentiles) {
			hilat = "High priority total latency";
			lolat = "Low priority total latency";
		} else {
			hilat = "High priority completion latency";
			lolat = "Low priority completion latency";
		}

		if (flags & GFIO_SLAT)
			gfio_show_lat(vbox, "Submission latency", min[0], max[0], mean[0], dev[0]);
		if (flags & GFIO_CLAT)
			gfio_show_lat(vbox, "Completion latency", min[1], max[1], mean[1], dev[1]);
		if (flags & GFIO_LAT)
			gfio_show_lat(vbox, "Total latency", min[2], max[2], mean[2], dev[2]);
		if (flags & GFIO_HILAT)
			gfio_show_lat(vbox, hilat, min[3], max[3], mean[3], dev[3]);
		if (flags & GFIO_LOLAT)
			gfio_show_lat(vbox, lolat, min[4], max[4], mean[4], dev[4]);
	}

	if (ts->slat_percentiles && flags & GFIO_SLAT)
		gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
				ts->io_u_plat[FIO_SLAT][ddir],
				ts->slat_stat[ddir].samples,
				"Submission");
	if (ts->clat_percentiles && flags & GFIO_CLAT) {
		gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
				ts->io_u_plat[FIO_CLAT][ddir],
				ts->clat_stat[ddir].samples,
				"Completion");
		if (!ts->lat_percentiles) {
			if (flags & GFIO_HILAT)
				gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
						ts->io_u_plat_high_prio[ddir],
						ts->clat_high_prio_stat[ddir].samples,
						"High priority completion");
			if (flags & GFIO_LOLAT)
				gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
						ts->io_u_plat_low_prio[ddir],
						ts->clat_low_prio_stat[ddir].samples,
						"Low priority completion");
		}
	}
	if (ts->lat_percentiles && flags & GFIO_LAT) {
		gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
				ts->io_u_plat[FIO_LAT][ddir],
				ts->lat_stat[ddir].samples,
				"Total");
		if (flags & GFIO_HILAT)
			gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
					ts->io_u_plat_high_prio[ddir],
					ts->clat_high_prio_stat[ddir].samples,
					"High priority total");
		if (flags & GFIO_LOLAT)
			gfio_show_clat_percentiles(gc, main_vbox, ts, ddir,
					ts->io_u_plat_low_prio[ddir],
					ts->clat_low_prio_stat[ddir].samples,
					"Low priority total");
	}

	free(io_p);
	free(bw_p);
	free(io_palt);
	free(bw_palt);
	free(iops_p);
}

static void __gfio_display_end_results(GtkWidget *win, struct gfio_client *gc,
				       struct thread_stat *ts,
				       struct group_run_stats *rs)
{
	GtkWidget *box, *vbox, *entry, *scroll;
	int i;

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	vbox = gtk_vbox_new(FALSE, 3);

	box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), vbox);

	gtk_notebook_append_page(GTK_NOTEBOOK(win), scroll, gtk_label_new(ts->name));

	entry = new_info_entry_in_frame(box, "Name");
	gtk_entry_set_text(GTK_ENTRY(entry), ts->name);
	if (strlen(ts->description)) {
		entry = new_info_entry_in_frame(box, "Description");
		gtk_entry_set_text(GTK_ENTRY(entry), ts->description);
	}
	entry = new_info_entry_in_frame(box, "Group ID");
	entry_set_int_value(entry, ts->groupid);
	entry = new_info_entry_in_frame(box, "Jobs");
	entry_set_int_value(entry, ts->members);
	gc->err_entry = entry = new_info_entry_in_frame(box, "Error");
	entry_set_int_value(entry, ts->error);
	entry = new_info_entry_in_frame(box, "PID");
	entry_set_int_value(entry, ts->pid);

	for (i = 0; i < DDIR_RWDIR_CNT; i++) {
		if (ts->io_bytes[i])
			gfio_show_ddir_status(gc, vbox, rs, ts, i);
	}

	gfio_show_latency_buckets(gc, vbox, ts);
	gfio_show_cpu_usage(vbox, ts);
	gfio_show_io_depths(vbox, ts);
}

void gfio_display_end_results(struct gfio_client *gc)
{
	struct gui_entry *ge = gc->ge;
	GtkWidget *res_notebook;
	int i;

	res_notebook = get_results_window(ge);

	for (i = 0; i < gc->nr_results; i++) {
		struct end_results *e = &gc->results[i];

		__gfio_display_end_results(res_notebook, gc, &e->ts, &e->gs);
	}

	if (gfio_disk_util_show(gc))
		gtk_widget_show_all(ge->results_window);
}

static void gfio_display_ts(struct fio_client *client, struct thread_stat *ts,
			    struct group_run_stats *rs)
{
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;

	gfio_add_end_results(gc, ts, rs);

	gdk_threads_enter();
	if (ge->results_window)
		__gfio_display_end_results(ge->results_notebook, gc, ts, rs);
	else
		gfio_display_end_results(gc);
	gdk_threads_leave();
}

static void gfio_client_removed(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;

	assert(gc->client == client);
	fio_put_client(gc->client);
	gc->client = NULL;
}

struct client_ops gfio_client_ops = {
	.text			= gfio_text_op,
	.disk_util		= gfio_disk_util_op,
	.thread_status		= gfio_thread_status_op,
	.group_stats		= gfio_group_stats_op,
	.jobs_eta		= gfio_update_client_eta,
	.eta			= gfio_update_all_eta,
	.probe			= gfio_probe_op,
	.quit			= gfio_quit_op,
	.add_job		= gfio_add_job_op,
	.update_job		= gfio_update_job_op,
	.timed_out		= gfio_client_timed_out,
	.stop			= gfio_client_stop,
	.start			= gfio_client_start,
	.job_start		= gfio_client_job_start,
	.removed		= gfio_client_removed,
	.eta_msec		= FIO_CLIENT_DEF_ETA_MSEC,
	.stay_connected		= 1,
	.client_type		= FIO_CLIENT_TYPE_GUI,
};
