/*
 * gfio - gui front end for fio - the flexible io tester
 *
 * Copyright (C) 2012 Stephen M. Cameron <stephenmcameron@gmail.com>
 * Copyright (C) 2012 Jens Axboe <axboe@kernel.dk>
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
#include <string.h>

#include <glib.h>
#include <cairo.h>
#include <gtk/gtk.h>

#include "fio.h"
#include "gfio.h"
#include "ghelpers.h"
#include "goptions.h"
#include "gerror.h"
#include "gclient.h"
#include "graph.h"

static int gfio_server_running;
static unsigned int gfio_graph_limit = 100;

GdkColor gfio_color_white;
GdkColor gfio_color_lightyellow;
const char *gfio_graph_font = GRAPH_DEFAULT_FONT;

typedef void (*clickfunction)(GtkWidget *widget, gpointer data);

static void connect_clicked(GtkWidget *widget, gpointer data);
static void start_job_clicked(GtkWidget *widget, gpointer data);
static void send_clicked(GtkWidget *widget, gpointer data);

static struct button_spec {
	const char *buttontext;
	clickfunction f;
	const char *tooltiptext[2];
	const int start_sensitive;
} buttonspeclist[] = {
	{
	  .buttontext		= "Connect",
	  .f			= connect_clicked,
	  .tooltiptext		= { "Disconnect from host", "Connect to host" },
	  .start_sensitive	= 1,
	},
	{
	  .buttontext		= "Send",
	  .f			= send_clicked,
	  .tooltiptext		= { "Send job description to host", NULL },
	  .start_sensitive	= 0,
	},
	{
	  .buttontext		= "Start Job",
	  .f			= start_job_clicked,
	  .tooltiptext		= { "Start the current job on the server", NULL },
	  .start_sensitive	= 0,
	},
};

static void setup_iops_graph(struct gfio_graphs *gg)
{
	struct graph *g;

	g = graph_new(DRAWING_AREA_XDIM / 2.0, DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(g, "IOPS (IOs/sec)");
	graph_x_title(g, "Time (secs)");
	gg->read_iops = graph_add_label(g, "Read IOPS");
	gg->write_iops = graph_add_label(g, "Write IOPS");
	gg->trim_iops = graph_add_label(g, "Trim IOPS");
	graph_set_color(g, gg->read_iops, GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	graph_set_color(g, gg->write_iops, GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	graph_set_color(g, gg->trim_iops, GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);
	line_graph_set_data_count_limit(g, gfio_graph_limit);
	graph_add_extra_space(g, 0.0, 0.0, 0.0, 0.0);
	graph_set_graph_all_zeroes(g, 0);
	gg->iops_graph = g;
}

static void setup_bandwidth_graph(struct gfio_graphs *gg)
{
	struct graph *g;

	g = graph_new(DRAWING_AREA_XDIM / 2.0, DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(g, "Bandwidth (bytes/sec)");
	graph_x_title(g, "Time (secs)");
	gg->read_bw = graph_add_label(g, "Read Bandwidth");
	gg->write_bw = graph_add_label(g, "Write Bandwidth");
	gg->trim_bw = graph_add_label(g, "Trim Bandwidth");
	graph_set_color(g, gg->read_bw, GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	graph_set_color(g, gg->write_bw, GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	graph_set_color(g, gg->trim_bw, GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);
	graph_set_base_offset(g, 1);
	line_graph_set_data_count_limit(g, 100);
	graph_add_extra_space(g, 0.0, 0.0, 0.0, 0.0);
	graph_set_graph_all_zeroes(g, 0);
	gg->bandwidth_graph = g;
}

static void setup_graphs(struct gfio_graphs *g)
{
	setup_iops_graph(g);
	setup_bandwidth_graph(g);
}

void clear_ge_ui_info(struct gui_entry *ge)
{
	gtk_label_set_text(GTK_LABEL(ge->probe.hostname), "");
	gtk_label_set_text(GTK_LABEL(ge->probe.os), "");
	gtk_label_set_text(GTK_LABEL(ge->probe.arch), "");
	gtk_label_set_text(GTK_LABEL(ge->probe.fio_ver), "");
#if 0
	/* should we empty it... */
	gtk_entry_set_text(GTK_ENTRY(ge->eta.name), "");
#endif
	multitext_update_entry(&ge->eta.iotype, 0, "");
	multitext_update_entry(&ge->eta.bs, 0, "");
	multitext_update_entry(&ge->eta.ioengine, 0, "");
	multitext_update_entry(&ge->eta.iodepth, 0, "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.jobs), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.files), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.read_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.read_iops), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.write_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.write_iops), "");
}

static void set_menu_entry_text(struct gui *ui, const char *path,
				const char *text)
{
	GtkWidget *w;

	w = gtk_ui_manager_get_widget(ui->uimanager, path);
	if (w)
		gtk_menu_item_set_label(GTK_MENU_ITEM(w), text);
	else
		fprintf(stderr, "gfio: can't find path %s\n", path);
}


static void set_menu_entry_visible(struct gui *ui, const char *path, int show)
{
	GtkWidget *w;

	w = gtk_ui_manager_get_widget(ui->uimanager, path);
	if (w)
		gtk_widget_set_sensitive(w, show);
	else
		fprintf(stderr, "gfio: can't find path %s\n", path);
}

static void set_job_menu_visible(struct gui *ui, int visible)
{
	set_menu_entry_visible(ui, "/MainMenu/JobMenu", visible);
}

static void set_view_results_visible(struct gui *ui, int visible)
{
	set_menu_entry_visible(ui, "/MainMenu/ViewMenu/Results", visible);
}

static const char *get_button_tooltip(struct button_spec *s, int sensitive)
{
	if (s->tooltiptext[sensitive])
		return s->tooltiptext[sensitive];

	return s->tooltiptext[0];
}

static GtkWidget *add_button(GtkWidget *buttonbox,
			     struct button_spec *buttonspec, gpointer data)
{
	GtkWidget *button = gtk_button_new_with_label(buttonspec->buttontext);
	gboolean sens = buttonspec->start_sensitive;

	g_signal_connect(button, "clicked", G_CALLBACK(buttonspec->f), data);
	gtk_box_pack_start(GTK_BOX(buttonbox), button, FALSE, FALSE, 3);

	sens = buttonspec->start_sensitive;
	gtk_widget_set_tooltip_text(button, get_button_tooltip(buttonspec, sens));
	gtk_widget_set_sensitive(button, sens);

	return button;
}

static void add_buttons(struct gui_entry *ge, struct button_spec *buttonlist,
			int nbuttons)
{
	int i;

	for (i = 0; i < nbuttons; i++)
		ge->button[i] = add_button(ge->buttonbox, &buttonlist[i], ge);
}

/*
 * Update sensitivity of job buttons and job menu items, based on the
 * state of the client.
 */
static void update_button_states(struct gui *ui, struct gui_entry *ge)
{
	unsigned int connect_state, send_state, start_state, edit_state;
	const char *connect_str = NULL;

	switch (ge->state) {
	default:
		gfio_report_error(ge, "Bad client state: %u\n", ge->state);
		/* fall through to new state */
	case GE_STATE_NEW:
		connect_state = 1;
		edit_state = 1;
		connect_str = "Connect";
		send_state = 0;
		start_state = 0;
		break;
	case GE_STATE_CONNECTED:
		connect_state = 1;
		edit_state = 1;
		connect_str = "Disconnect";
		send_state = 1;
		start_state = 0;
		break;
	case GE_STATE_JOB_SENT:
		connect_state = 1;
		edit_state = 1;
		connect_str = "Disconnect";
		send_state = 0;
		start_state = 1;
		break;
	case GE_STATE_JOB_STARTED:
		connect_state = 1;
		edit_state = 1;
		connect_str = "Disconnect";
		send_state = 0;
		start_state = 1;
		break;
	case GE_STATE_JOB_RUNNING:
		connect_state = 1;
		edit_state = 0;
		connect_str = "Disconnect";
		send_state = 0;
		start_state = 0;
		break;
	case GE_STATE_JOB_DONE:
		connect_state = 1;
		edit_state = 0;
		connect_str = "Connect";
		send_state = 0;
		start_state = 0;
		break;
	}

	gtk_widget_set_sensitive(ge->button[GFIO_BUTTON_CONNECT], connect_state);
	gtk_widget_set_sensitive(ge->button[GFIO_BUTTON_SEND], send_state);
	gtk_widget_set_sensitive(ge->button[GFIO_BUTTON_START], start_state);
	gtk_button_set_label(GTK_BUTTON(ge->button[GFIO_BUTTON_CONNECT]), connect_str);
	gtk_widget_set_tooltip_text(ge->button[GFIO_BUTTON_CONNECT], get_button_tooltip(&buttonspeclist[GFIO_BUTTON_CONNECT], connect_state));

	set_menu_entry_visible(ui, "/MainMenu/JobMenu/Connect", connect_state);
	set_menu_entry_text(ui, "/MainMenu/JobMenu/Connect", connect_str);

	set_menu_entry_visible(ui, "/MainMenu/JobMenu/Edit job", edit_state);
	set_menu_entry_visible(ui, "/MainMenu/JobMenu/Send job", send_state);
	set_menu_entry_visible(ui, "/MainMenu/JobMenu/Start job", start_state);

	if (ge->client && ge->client->nr_results)
		set_view_results_visible(ui, 1);
	else
		set_view_results_visible(ui, 0);
}

void gfio_set_state(struct gui_entry *ge, unsigned int state)
{
	ge->state = state;
	update_button_states(ge->ui, ge);
}

static void gfio_ui_setup_log(struct gui *ui)
{
	GtkTreeSelection *selection;
	GtkListStore *model;
	GtkWidget *tree_view;

	model = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);

	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(model));
	gtk_widget_set_can_focus(tree_view, FALSE);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(GTK_TREE_SELECTION(selection), GTK_SELECTION_BROWSE);
	g_object_set(G_OBJECT(tree_view), "headers-visible", TRUE,
		"enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_BOTH, NULL);

	tree_view_column(tree_view, 0, "Time", ALIGN_RIGHT | UNSORTABLE);
	tree_view_column(tree_view, 1, "Host", ALIGN_RIGHT | UNSORTABLE);
	tree_view_column(tree_view, 2, "Level", ALIGN_RIGHT | UNSORTABLE);
	tree_view_column(tree_view, 3, "Text", ALIGN_LEFT | UNSORTABLE);

	ui->log_model = model;
	ui->log_tree = tree_view;
}

static gint on_config_drawing_area(GtkWidget *w, GdkEventConfigure *event,
				   gpointer data)
{
	guint width = gtk_widget_get_allocated_width(w);
	guint height = gtk_widget_get_allocated_height(w);
	struct gfio_graphs *g = data;

	graph_set_size(g->iops_graph, width / 2.0, height);
	graph_set_position(g->iops_graph, width / 2.0, 0.0);
	graph_set_size(g->bandwidth_graph, width / 2.0, height);
	graph_set_position(g->bandwidth_graph, 0, 0);
	return TRUE;
}

static void draw_graph(struct graph *g, cairo_t *cr)
{
	line_graph_draw(g, cr);
	cairo_stroke(cr);
}

static gboolean graph_tooltip(GtkWidget *w, gint x, gint y,
			      gboolean keyboard_mode, GtkTooltip *tooltip,
			      gpointer data)
{
	struct gfio_graphs *g = data;
	const char *text = NULL;

	if (graph_contains_xy(g->iops_graph, x, y))
		text = graph_find_tooltip(g->iops_graph, x, y);
	else if (graph_contains_xy(g->bandwidth_graph, x, y))
		text = graph_find_tooltip(g->bandwidth_graph, x, y);

	if (text) {
		gtk_tooltip_set_text(tooltip, text);
		return TRUE;
	}

	return FALSE;
}

static int on_expose_drawing_area(GtkWidget *w, GdkEvent *event, gpointer p)
{
	struct gfio_graphs *g = p;
	cairo_t *cr;

	cr = gdk_cairo_create(gtk_widget_get_window(w));

	if (graph_has_tooltips(g->iops_graph) ||
	    graph_has_tooltips(g->bandwidth_graph)) {
		g_object_set(w, "has-tooltip", TRUE, NULL);
		g_signal_connect(w, "query-tooltip", G_CALLBACK(graph_tooltip), g);
	}

	cairo_set_source_rgb(cr, 0, 0, 0);
	draw_graph(g->iops_graph, cr);
	draw_graph(g->bandwidth_graph, cr);
	cairo_destroy(cr);

	return FALSE;
}

/*
 * FIXME: need more handling here
 */
static void ge_destroy(struct gui_entry *ge)
{
	struct gfio_client *gc = ge->client;

	if (gc) {
		if (gc->client) {
			if (ge->state >= GE_STATE_CONNECTED)
				fio_client_terminate(gc->client);

			fio_put_client(gc->client);
		}
		free(gc);
	}

	g_hash_table_remove(ge->ui->ge_hash, &ge->page_num);

	free(ge->job_file);
	free(ge->host);
	free(ge);
}

static void ge_widget_destroy(GtkWidget *w, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	ge_destroy(ge);
}

static void gfio_quit(struct gui *ui)
{
	gtk_main_quit();
}

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
			 gpointer data)
{
	struct gui *ui = (struct gui *) data;

	gfio_quit(ui);
}

static void *job_thread(void *arg)
{
	struct gui *ui = arg;

	ui->handler_running = 1;
	fio_handle_clients(&gfio_client_ops);
	ui->handler_running = 0;
	return NULL;
}

static int send_job_file(struct gui_entry *ge)
{
	struct gfio_client *gc = ge->client;
	int ret = 0;

	/*
	 * Prune old options, we are expecting the return options
	 * when the job file is parsed remotely and returned to us.
	 */
	while (!flist_empty(&gc->o_list)) {
		struct gfio_client_options *gco;

		gco = flist_entry(gc->o_list.next, struct gfio_client_options, list);
		flist_del(&gco->list);
		free(gco);
	}

	ret = fio_client_send_ini(gc->client, ge->job_file);
	if (!ret)
		return 0;

	gfio_report_error(ge, "Failed to send file %s: %s\n", ge->job_file, strerror(-ret));
	return 1;
}

static void *server_thread(void *arg)
{
	is_backend = 1;
	gfio_server_running = 1;
	fio_start_server(NULL);
	gfio_server_running = 0;
	return NULL;
}

static void gfio_start_server(struct gui *ui)
{
	if (!gfio_server_running) {
		gfio_server_running = 1;
		pthread_create(&ui->server_t, NULL, server_thread, NULL);
		pthread_detach(ui->server_t);
	}
}

static void start_job_clicked(__attribute__((unused)) GtkWidget *widget,
			      gpointer data)
{
	struct gui_entry *ge = data;
	struct gfio_client *gc = ge->client;

	if (gc)
		fio_start_client(gc->client);
}

static void file_open(GtkWidget *w, gpointer data);

struct connection_widgets
{
	GtkWidget *hentry;
	GtkWidget *combo;
	GtkWidget *button;
};

static void hostname_cb(GtkEntry *entry, gpointer data)
{
	struct connection_widgets *cw = data;
	int uses_net = 0, is_localhost = 0;
	const gchar *text;
	gchar *ctext;

	/*
	 * Check whether to display the 'auto start backend' box
	 * or not. Show it if we are a localhost and using network,
	 * or using a socket.
	 */
	ctext = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(cw->combo));
	if (!ctext || !strncmp(ctext, "IPv4", 4) || !strncmp(ctext, "IPv6", 4))
		uses_net = 1;
	g_free(ctext);

	if (uses_net) {
		text = gtk_entry_get_text(GTK_ENTRY(cw->hentry));
		if (!strcmp(text, "127.0.0.1") || !strcmp(text, "localhost") ||
		    !strcmp(text, "::1") || !strcmp(text, "ip6-localhost") ||
		    !strcmp(text, "ip6-loopback"))
			is_localhost = 1;
	}

	if (!uses_net || is_localhost) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cw->button), 1);
		gtk_widget_set_sensitive(cw->button, 1);
	} else {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cw->button), 0);
		gtk_widget_set_sensitive(cw->button, 0);
	}
}

static int get_connection_details(struct gui_entry *ge)
{
	GtkWidget *dialog, *box, *vbox, *hbox, *frame, *pentry;
	struct connection_widgets cw;
	struct gui *ui = ge->ui;
	char *typeentry;

	if (ge->host)
		return 0;

	dialog = gtk_dialog_new_with_buttons("Connection details",
			GTK_WINDOW(ui->window),
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
	cw.hentry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(cw.hentry), "localhost");
	gtk_box_pack_start(GTK_BOX(hbox), cw.hentry, TRUE, TRUE, 0);

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

	cw.combo = gtk_combo_box_text_new();
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(cw.combo), "IPv4");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(cw.combo), "IPv6");
	gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(cw.combo), "local socket");
	gtk_combo_box_set_active(GTK_COMBO_BOX(cw.combo), 0);

	gtk_container_add(GTK_CONTAINER(hbox), cw.combo);

	frame = gtk_frame_new("Options");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	box = gtk_vbox_new(FALSE, 10);
	gtk_container_add(GTK_CONTAINER(frame), box);

	hbox = gtk_hbox_new(TRUE, 4);
	gtk_box_pack_start(GTK_BOX(box), hbox, FALSE, FALSE, 0);

	cw.button = gtk_check_button_new_with_label("Auto-spawn fio backend");
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(cw.button), 1);
	gtk_widget_set_tooltip_text(cw.button, "When running fio locally, it is necessary to have the backend running on the same system. If this is checked, gfio will start the backend automatically for you if it isn't already running.");
	gtk_box_pack_start(GTK_BOX(hbox), cw.button, FALSE, FALSE, 6);

	/*
	 * Connect edit signal, so we can show/not-show the auto start button
	 */
	g_signal_connect(G_OBJECT(cw.hentry), "changed", G_CALLBACK(hostname_cb), &cw);
	g_signal_connect(G_OBJECT(cw.combo), "changed", G_CALLBACK(hostname_cb), &cw);

	gtk_widget_show_all(dialog);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return 1;
	}

	ge->host = strdup(gtk_entry_get_text(GTK_ENTRY(cw.hentry)));
	ge->port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(pentry));

	typeentry = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(cw.combo));
	if (!typeentry || !strncmp(typeentry, "IPv4", 4))
		ge->type = Fio_client_ipv4;
	else if (!strncmp(typeentry, "IPv6", 4))
		ge->type = Fio_client_ipv6;
	else
		ge->type = Fio_client_socket;
	g_free(typeentry);

	ge->server_start = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cw.button));

	gtk_widget_destroy(dialog);
	return 0;
}

static void gfio_set_client(struct gfio_client *gc, struct fio_client *client)
{
	gc->client = fio_get_client(client);
	client->client_data = gc;
}

static void gfio_client_added(struct gui_entry *ge, struct fio_client *client)
{
	struct gfio_client_options *gco;
	struct gfio_client *gc;

	gc = calloc(1, sizeof(*gc));
	INIT_FLIST_HEAD(&gc->o_list);
	gc->ge = ge;
	ge->client = gc;
	gfio_set_client(gc, client);

	/*
	 * Just add a default set of options, need to consider how best
	 * to handle this
	 */
	gco = calloc(1, sizeof(*gco));
	INIT_FLIST_HEAD(&gco->list);
	options_default_fill(&gco->o);
	flist_add_tail(&gco->list, &gc->o_list);
	gc->o_list_nr++;
}

static void gfio_clear_graph_data(struct gfio_graphs *g)
{
	graph_clear_values(g->iops_graph);
	graph_clear_values(g->bandwidth_graph);
}

static void connect_clicked(GtkWidget *widget, gpointer data)
{
	struct gui_entry *ge = data;
	struct gfio_client *gc = ge->client;

	if (ge->state == GE_STATE_NEW) {
		int ret;

		if (!ge->job_file)
			file_open(widget, ge->ui);
		if (!ge->job_file)
			return;

		gc = ge->client;

		if (!gc->client) {
			struct fio_client *client;

			if (get_connection_details(ge)) {
				gfio_report_error(ge, "Failed to get connection details\n");
				return;
			}

			client = fio_client_add_explicit(&gfio_client_ops, ge->host, ge->type, ge->port);
			if (!client) {
				gfio_report_error(ge, "Failed to add client %s\n", ge->host);
				free(ge->host);
				ge->host = NULL;
				return;
			}
			gfio_set_client(gc, client);
		}

		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ge->thread_status_pb), "No jobs running");
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ge->thread_status_pb), 0.0);
		ret = fio_client_connect(gc->client);
		if (!ret) {
			if (!ge->ui->handler_running)
				pthread_create(&ge->ui->t, NULL, job_thread, ge->ui);
			gfio_set_state(ge, GE_STATE_CONNECTED);
			gfio_clear_graph_data(&ge->graphs);
		} else {
			gfio_report_error(ge, "Failed to connect to %s: %s\n", ge->client->client->hostname, strerror(-ret));
		}
	} else {
		fio_client_terminate(gc->client);
		gfio_set_state(ge, GE_STATE_NEW);
		clear_ge_ui_info(ge);
	}
}

static void send_clicked(GtkWidget *widget, gpointer data)
{
	struct gui_entry *ge = data;

	if (send_job_file(ge))
		gtk_widget_set_sensitive(ge->button[GFIO_BUTTON_START], 1);
}

static GtkWidget *new_client_page(struct gui_entry *ge);

static struct gui_entry *alloc_new_gui_entry(struct gui *ui)
{
	struct gui_entry *ge;

	ge = malloc(sizeof(*ge));
	memset(ge, 0, sizeof(*ge));
	ge->state = GE_STATE_NEW;
	ge->ui = ui;
	return ge;
}

static struct gui_entry *get_new_ge_with_tab(struct gui *ui, const char *name)
{
	struct gui_entry *ge;

	ge = alloc_new_gui_entry(ui);

	ge->vbox = new_client_page(ge);
	g_signal_connect(ge->vbox, "destroy", G_CALLBACK(ge_widget_destroy), ge);

	ge->page_label = gtk_label_new(name);
	ge->page_num = gtk_notebook_append_page(GTK_NOTEBOOK(ui->notebook), ge->vbox, ge->page_label);

	g_hash_table_insert(ui->ge_hash, &ge->page_num, ge);

	gtk_widget_show_all(ui->window);
	return ge;
}

static void file_new(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_new_ge_with_tab(ui, "Untitled");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(ui->notebook), ge->page_num);
}

/*
 * Return the 'ge' corresponding to the tab. If the active tab is the
 * main tab, open a new tab.
 */
static struct gui_entry *get_ge_from_page(struct gui *ui, gint cur_page,
					  int *created)
{
	if (!cur_page) {
		if (created)
			*created = 1;
		return get_new_ge_with_tab(ui, "Untitled");
	}

	if (created)
		*created = 0;

	return g_hash_table_lookup(ui->ge_hash, &cur_page);
}

static struct gui_entry *get_ge_from_cur_tab(struct gui *ui)
{
	gint cur_page;

	/*
	 * Main tab is tab 0, so any current page other than 0 holds
	 * a ge entry.
	 */
	cur_page = gtk_notebook_get_current_page(GTK_NOTEBOOK(ui->notebook));
	if (cur_page)
		return get_ge_from_page(ui, cur_page, NULL);

	return NULL;
}

static void file_close(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	/*
	 * Can't close the main tab
	 */
	ge = get_ge_from_cur_tab(ui);
	if (ge) {
		gtk_widget_destroy(ge->vbox);
		return;
	}

	if (g_hash_table_size(ui->ge_hash)) {
		gfio_report_info(ui, "Error", "The main page view cannot be closed\n");
		return;
	}

	gfio_quit(ui);
}

static void file_add_recent(struct gui *ui, const gchar *uri)
{
	GtkRecentData grd;

	memset(&grd, 0, sizeof(grd));
	grd.display_name = strdup("gfio");
	grd.description = strdup("Fio job file");
	grd.mime_type = strdup(GFIO_MIME);
	grd.app_name = strdup(g_get_application_name());
	grd.app_exec = strdup("gfio %f/%u");

	gtk_recent_manager_add_full(ui->recentmanager, uri, &grd);
}

static gchar *get_filename_from_uri(const gchar *uri)
{
	if (strncmp(uri, "file://", 7))
		return strdup(uri);

	return strdup(uri + 7);
}

static int do_file_open(struct gui_entry *ge, const gchar *uri)
{
	struct fio_client *client;

	assert(!ge->job_file);

	ge->job_file = get_filename_from_uri(uri);

	client = fio_client_add_explicit(&gfio_client_ops, ge->host, ge->type, ge->port);
	if (client) {
		char *label = strdup(uri);

		basename(label);
		gtk_label_set_text(GTK_LABEL(ge->page_label), basename(label));
		free(label);

		gfio_client_added(ge, client);
		file_add_recent(ge->ui, uri);
		return 0;
	}

	gfio_report_error(ge, "Failed to add client %s\n", ge->host);
	free(ge->host);
	ge->host = NULL;
	free(ge->job_file);
	ge->job_file = NULL;
	return 1;
}

static int do_file_open_with_tab(struct gui *ui, const gchar *uri)
{
	struct gui_entry *ge;
	gint cur_page;
	int ret, ge_is_new = 0;

	/*
	 * Creates new tab if current tab is the main window, or the
	 * current tab already has a client.
	 */
	cur_page = gtk_notebook_get_current_page(GTK_NOTEBOOK(ui->notebook));
	ge = get_ge_from_page(ui, cur_page, &ge_is_new);
	if (ge->client) {
		ge = get_new_ge_with_tab(ui, "Untitled");
		ge_is_new = 1;
	}

	gtk_notebook_set_current_page(GTK_NOTEBOOK(ui->notebook), ge->page_num);

	if (get_connection_details(ge)) {
		if (ge_is_new)
			gtk_widget_destroy(ge->vbox);

		return 1;
	}

	ret = do_file_open(ge, uri);

	if (!ret) {
		if (ge->server_start)
			gfio_start_server(ui);
	} else {
		if (ge_is_new)
			gtk_widget_destroy(ge->vbox);
	}

	return ret;
}

static void recent_open(GtkAction *action, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	GtkRecentInfo *info;
	const gchar *uri;

	info = g_object_get_data(G_OBJECT(action), "gtk-recent-info");
	uri = gtk_recent_info_get_uri(info);

	do_file_open_with_tab(ui, uri);
}

static void file_open(GtkWidget *w, gpointer data)
{
	struct gui *ui = data;
	GtkWidget *dialog;
	GtkFileFilter *filter;
	gchar *filename;

	dialog = gtk_file_chooser_dialog_new("Open File",
		GTK_WINDOW(ui->window),
		GTK_FILE_CHOOSER_ACTION_OPEN,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
		NULL);
	gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), FALSE);

	filter = gtk_file_filter_new();
	gtk_file_filter_add_pattern(filter, "*.fio");
	gtk_file_filter_add_pattern(filter, "*.job");
	gtk_file_filter_add_pattern(filter, "*.ini");
	gtk_file_filter_add_mime_type(filter, GFIO_MIME);
	gtk_file_filter_set_name(filter, "Fio job file");
	gtk_file_chooser_set_filter(GTK_FILE_CHOOSER(dialog), filter);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return;
	}

	filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));

	gtk_widget_destroy(dialog);

	do_file_open_with_tab(ui, filename);
	g_free(filename);
}

static void file_save(GtkWidget *w, gpointer data)
{
	struct gui *ui = data;
	GtkWidget *dialog;

	dialog = gtk_file_chooser_dialog_new("Save File",
		GTK_WINDOW(ui->window),
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

static void view_log_destroy(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;

	g_object_ref(G_OBJECT(ui->log_tree));
	gtk_container_remove(GTK_CONTAINER(w), ui->log_tree);
	gtk_widget_destroy(w);
	ui->log_view = NULL;
}

void gfio_view_log(struct gui *ui)
{
	GtkWidget *win, *scroll, *vbox, *box;

	if (ui->log_view)
		return;

	ui->log_view = win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "Log");
	gtk_window_set_default_size(GTK_WINDOW(win), 700, 500);

	scroll = gtk_scrolled_window_new(NULL, NULL);

	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	box = gtk_hbox_new(TRUE, 0);
	gtk_box_pack_start(GTK_BOX(box), ui->log_tree, TRUE, TRUE, 0);
	g_signal_connect(box, "destroy", G_CALLBACK(view_log_destroy), ui);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), box);

	vbox = gtk_vbox_new(TRUE, 5);
	gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

	gtk_container_add(GTK_CONTAINER(win), vbox);
	gtk_widget_show_all(win);
}

static void view_log(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;

	gfio_view_log(ui);
}

static void connect_job_entry(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (ge)
		connect_clicked(w, ge);
}

static void send_job_entry(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (ge)
		send_clicked(w, ge);
}

static void edit_job_entry(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (ge && ge->client)
		gopt_get_options_window(ui->window, ge->client);
}

static void start_job_entry(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (ge)
		start_job_clicked(w, ge);
}

static void view_results(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gfio_client *gc;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (!ge)
		return;

	if (ge->results_window)
		return;

	gc = ge->client;
	if (gc && gc->nr_results)
		gfio_display_end_results(gc);
}

static void __update_graph_settings(struct gfio_graphs *g)
{
	line_graph_set_data_count_limit(g->iops_graph, gfio_graph_limit);
	graph_set_font(g->iops_graph, gfio_graph_font);
	line_graph_set_data_count_limit(g->bandwidth_graph, gfio_graph_limit);
	graph_set_font(g->bandwidth_graph, gfio_graph_font);
}

static void ge_update_settings_fn(gpointer key, gpointer value, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) value;
	GdkEvent *ev;

	__update_graph_settings(&ge->graphs);

	ev = gdk_event_new(GDK_EXPOSE);
	g_signal_emit_by_name(G_OBJECT(ge->graphs.drawing_area), GFIO_DRAW_EVENT, GTK_WIDGET(ge->graphs.drawing_area), ev, &ge->graphs);
	gdk_event_free(ev);
}

static void update_graph_limits(void)
{
	struct gui *ui = &main_ui;
	GdkEvent *ev;

	__update_graph_settings(&ui->graphs);

	ev = gdk_event_new(GDK_EXPOSE);
	g_signal_emit_by_name(G_OBJECT(ui->graphs.drawing_area), GFIO_DRAW_EVENT, GTK_WIDGET(ui->graphs.drawing_area), ev, &ui->graphs);
	gdk_event_free(ev);

	g_hash_table_foreach(ui->ge_hash, ge_update_settings_fn, NULL);
}

static void preferences(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog, *frame, *box, **buttons, *vbox, *font;
	GtkWidget *hbox, *spin, *entry, *spin_int;
	struct gui *ui = (struct gui *) data;
	int i;

	dialog = gtk_dialog_new_with_buttons("Preferences",
		GTK_WINDOW(ui->window),
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
		GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
		NULL);

	frame = gtk_frame_new("Graphing");
	vbox = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	vbox = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	entry = gtk_label_new("Font face to use for graph labels");
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 5);

	font = gtk_font_button_new_with_font(gfio_graph_font);
	gtk_box_pack_start(GTK_BOX(hbox), font, FALSE, FALSE, 5);

	box = gtk_vbox_new(FALSE, 6);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);

	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 5);
	entry = gtk_label_new("Maximum number of data points in graph (seconds)");
	gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 5);

	spin = create_spinbutton(hbox, 10, 1000000, gfio_graph_limit);

	box = gtk_vbox_new(FALSE, 6);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);

	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(box), hbox, TRUE, TRUE, 5);
	entry = gtk_label_new("Client ETA request interval (msec)");
	gtk_box_pack_start(GTK_BOX(hbox), entry, FALSE, FALSE, 5);

	spin_int = create_spinbutton(hbox, 100, 100000, gfio_client_ops.eta_msec);
	frame = gtk_frame_new("Debug logging");
	vbox = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);
	vbox = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	box = gtk_hbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(vbox), box);

	buttons = malloc(sizeof(GtkWidget *) * FD_DEBUG_MAX);

	for (i = 0; i < FD_DEBUG_MAX; i++) {
		if (i == 7) {
			box = gtk_hbox_new(FALSE, 6);
			gtk_container_add(GTK_CONTAINER(vbox), box);
		}


		buttons[i] = gtk_check_button_new_with_label(debug_levels[i].name);
		gtk_widget_set_tooltip_text(buttons[i], debug_levels[i].help);
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

	gfio_graph_font = strdup(gtk_font_button_get_font_name(GTK_FONT_BUTTON(font)));
	gfio_graph_limit = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin));
	update_graph_limits();
	gfio_client_ops.eta_msec = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(spin_int));

	gtk_widget_destroy(dialog);
}

static void about_dialog(GtkWidget *w, gpointer data)
{
	const char *authors[] = {
		"Jens Axboe <axboe@kernel.dk>",
		"Stephen Carmeron <stephenmcameron@gmail.com>",
		NULL
	};
	const char *license[] = {
		"Fio is free software; you can redistribute it and/or modify "
		"it under the terms of the GNU General Public License as published by "
		"the Free Software Foundation; either version 2 of the License, or "
		"(at your option) any later version.\n",
		"Fio is distributed in the hope that it will be useful, "
		"but WITHOUT ANY WARRANTY; without even the implied warranty of "
		"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the "
		"GNU General Public License for more details.\n",
		"You should have received a copy of the GNU General Public License "
		"along with Fio; if not, write to the Free Software Foundation, Inc., "
		"51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA\n"
	};
	char *license_trans;

	license_trans = g_strconcat(license[0], "\n", license[1], "\n",
				     license[2], "\n", NULL);

	gtk_show_about_dialog(NULL,
		"program-name", "gfio",
		"comments", "Gtk2 UI for fio",
		"license", license_trans,
		"website", "http://git.kernel.dk/?p=fio.git;a=summary",
		"authors", authors,
		"version", fio_version_string,
		"copyright", "© 2012 Jens Axboe <axboe@kernel.dk>",
		"logo-icon-name", "fio",
		/* Must be last: */
		"wrap-license", TRUE,
		NULL);

	g_free(license_trans);
}

static GtkActionEntry menu_items[] = {
	{ "FileMenuAction", GTK_STOCK_FILE, "File", NULL, NULL, NULL},
	{ "ViewMenuAction", GTK_STOCK_FILE, "View", NULL, NULL, NULL},
	{ "JobMenuAction", GTK_STOCK_FILE, "Job", NULL, NULL, NULL},
	{ "HelpMenuAction", GTK_STOCK_HELP, "Help", NULL, NULL, NULL},
	{ "NewFile", GTK_STOCK_NEW, "New", "<Control>N", NULL, G_CALLBACK(file_new) },
	{ "CloseFile", GTK_STOCK_CLOSE, "Close", "<Control>W", NULL, G_CALLBACK(file_close) },
	{ "OpenFile", GTK_STOCK_OPEN, NULL,   "<Control>O", NULL, G_CALLBACK(file_open) },
	{ "SaveFile", GTK_STOCK_SAVE, NULL,   "<Control>S", NULL, G_CALLBACK(file_save) },
	{ "Preferences", GTK_STOCK_PREFERENCES, NULL, "<Control>p", NULL, G_CALLBACK(preferences) },
	{ "ViewLog", NULL, "Log", "<Control>l", NULL, G_CALLBACK(view_log) },
	{ "ViewResults", NULL, "Results", "<Control>R", NULL, G_CALLBACK(view_results) },
	{ "ConnectJob", NULL, "Connect", "<Control>D", NULL, G_CALLBACK(connect_job_entry) },
	{ "EditJob", NULL, "Edit job", "<Control>E", NULL, G_CALLBACK(edit_job_entry) },
	{ "SendJob", NULL, "Send job", "<Control>X", NULL, G_CALLBACK(send_job_entry) },
	{ "StartJob", NULL, "Start job", "<Control>L", NULL, G_CALLBACK(start_job_entry) },
	{ "Quit", GTK_STOCK_QUIT, NULL,   "<Control>Q", NULL, G_CALLBACK(quit_clicked) },
	{ "About", GTK_STOCK_ABOUT, NULL,  NULL, NULL, G_CALLBACK(about_dialog) },
};
static gint nmenu_items = sizeof(menu_items) / sizeof(menu_items[0]);

static const gchar *ui_string = " \
	<ui> \
		<menubar name=\"MainMenu\"> \
			<menu name=\"FileMenu\" action=\"FileMenuAction\"> \
				<menuitem name=\"New\" action=\"NewFile\" /> \
				<menuitem name=\"Open\" action=\"OpenFile\" /> \
				<menuitem name=\"Close\" action=\"CloseFile\" /> \
				<separator name=\"Separator1\"/> \
				<menuitem name=\"Save\" action=\"SaveFile\" /> \
				<separator name=\"Separator2\"/> \
				<menuitem name=\"Preferences\" action=\"Preferences\" /> \
				<separator name=\"Separator3\"/> \
				<placeholder name=\"FileRecentFiles\"/> \
				<separator name=\"Separator4\"/> \
				<menuitem name=\"Quit\" action=\"Quit\" /> \
			</menu> \
			<menu name=\"JobMenu\" action=\"JobMenuAction\"> \
				<menuitem name=\"Connect\" action=\"ConnectJob\" /> \
				<separator name=\"Separator5\"/> \
				<menuitem name=\"Edit job\" action=\"EditJob\" /> \
				<menuitem name=\"Send job\" action=\"SendJob\" /> \
				<separator name=\"Separator6\"/> \
				<menuitem name=\"Start job\" action=\"StartJob\" /> \
			</menu>\
			<menu name=\"ViewMenu\" action=\"ViewMenuAction\"> \
				<menuitem name=\"Results\" action=\"ViewResults\" /> \
				<separator name=\"Separator7\"/> \
				<menuitem name=\"Log\" action=\"ViewLog\" /> \
			</menu>\
			<menu name=\"Help\" action=\"HelpMenuAction\"> \
				<menuitem name=\"About\" action=\"About\" /> \
			</menu> \
		</menubar> \
	</ui> \
";

static GtkWidget *get_menubar_menu(GtkWidget *window, GtkUIManager *ui_manager,
				   struct gui *ui)
{
	GtkActionGroup *action_group;
	GError *error = 0;

	action_group = gtk_action_group_new("Menu");
	gtk_action_group_add_actions(action_group, menu_items, nmenu_items, ui);

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

static void combo_entry_changed(GtkComboBox *box, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;
	gint index;

	index = gtk_combo_box_get_active(box);

	multitext_set_entry(&ge->eta.iotype, index);
	multitext_set_entry(&ge->eta.bs, index);
	multitext_set_entry(&ge->eta.ioengine, index);
	multitext_set_entry(&ge->eta.iodepth, index);
}

static void combo_entry_destroy(GtkWidget *widget, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	multitext_free(&ge->eta.iotype);
	multitext_free(&ge->eta.bs);
	multitext_free(&ge->eta.ioengine);
	multitext_free(&ge->eta.iodepth);
}

static GtkWidget *new_client_page(struct gui_entry *ge)
{
	GtkWidget *main_vbox, *probe, *probe_frame, *probe_box;
	GtkWidget *scrolled_window, *bottom_align, *top_align, *top_vbox;

	main_vbox = gtk_vbox_new(FALSE, 3);

	top_align = gtk_alignment_new(0, 0, 1, 0);
	top_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(top_align), top_vbox);
	gtk_box_pack_start(GTK_BOX(main_vbox), top_align, FALSE, FALSE, 0);

	probe = gtk_frame_new("Job");
	gtk_box_pack_start(GTK_BOX(main_vbox), probe, FALSE, FALSE, 3);
	probe_frame = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(probe), probe_frame);

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, FALSE, FALSE, 3);
	ge->probe.hostname = new_info_label_in_frame(probe_box, "Host");
	ge->probe.os = new_info_label_in_frame(probe_box, "OS");
	ge->probe.arch = new_info_label_in_frame(probe_box, "Architecture");
	ge->probe.fio_ver = new_info_label_in_frame(probe_box, "Fio version");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, FALSE, FALSE, 3);

	ge->eta.names = new_combo_entry_in_frame(probe_box, "Jobs");
	g_signal_connect(ge->eta.names, "changed", G_CALLBACK(combo_entry_changed), ge);
	g_signal_connect(ge->eta.names, "destroy", G_CALLBACK(combo_entry_destroy), ge);
	ge->eta.iotype.entry = new_info_entry_in_frame(probe_box, "IO");
	ge->eta.bs.entry = new_info_entry_in_frame(probe_box, "Blocksize (Read/Write)");
	ge->eta.ioengine.entry = new_info_entry_in_frame(probe_box, "IO Engine");
	ge->eta.iodepth.entry = new_info_entry_in_frame(probe_box, "IO Depth");
	ge->eta.jobs = new_info_entry_in_frame(probe_box, "Jobs");
	ge->eta.files = new_info_entry_in_frame(probe_box, "Open files");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, FALSE, FALSE, 3);
	ge->eta.read_bw = new_info_entry_in_frame_rgb(probe_box, "Read BW", GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	ge->eta.read_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	ge->eta.write_bw = new_info_entry_in_frame_rgb(probe_box, "Write BW", GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	ge->eta.write_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	ge->eta.trim_bw = new_info_entry_in_frame_rgb(probe_box, "Trim BW", GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);
	ge->eta.trim_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);

	/*
	 * Only add this if we have a commit rate
	 */
#if 0
	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);

	ge->eta.cr_bw = new_info_label_in_frame(probe_box, "Commit BW");
	ge->eta.cr_iops = new_info_label_in_frame(probe_box, "Commit IOPS");

	ge->eta.cw_bw = new_info_label_in_frame(probe_box, "Commit BW");
	ge->eta.cw_iops = new_info_label_in_frame(probe_box, "Commit IOPS");
#endif

	/*
	 * Set up a drawing area and IOPS and bandwidth graphs
	 */
	ge->graphs.drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(ge->graphs.drawing_area),
		DRAWING_AREA_XDIM, DRAWING_AREA_YDIM);
	gtk_widget_modify_bg(ge->graphs.drawing_area, GTK_STATE_NORMAL, &gfio_color_lightyellow);
	g_signal_connect(G_OBJECT(ge->graphs.drawing_area), GFIO_DRAW_EVENT,
				G_CALLBACK(on_expose_drawing_area), &ge->graphs);
	g_signal_connect(G_OBJECT(ge->graphs.drawing_area), "configure_event",
				G_CALLBACK(on_config_drawing_area), &ge->graphs);
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
					GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window),
					ge->graphs.drawing_area);
	gtk_box_pack_start(GTK_BOX(main_vbox), scrolled_window, TRUE, TRUE, 0);

	setup_graphs(&ge->graphs);

	/*
	 * Set up alignments for widgets at the bottom of ui,
	 * align bottom left, expand horizontally but not vertically
	 */
	bottom_align = gtk_alignment_new(0, 1, 1, 0);
	ge->buttonbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(bottom_align), ge->buttonbox);
	gtk_box_pack_start(GTK_BOX(main_vbox), bottom_align, FALSE, FALSE, 0);

	add_buttons(ge, buttonspeclist, ARRAY_SIZE(buttonspeclist));

	/*
	 * Set up thread status progress bar
	 */
	ge->thread_status_pb = gtk_progress_bar_new();
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ge->thread_status_pb), 0.0);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ge->thread_status_pb), "No connections");
	gtk_container_add(GTK_CONTAINER(ge->buttonbox), ge->thread_status_pb);


	return main_vbox;
}

static GtkWidget *new_main_page(struct gui *ui)
{
	GtkWidget *main_vbox, *probe, *probe_frame, *probe_box;
	GtkWidget *scrolled_window, *bottom_align, *top_align, *top_vbox;

	main_vbox = gtk_vbox_new(FALSE, 3);

	/*
	 * Set up alignments for widgets at the top of ui,
	 * align top left, expand horizontally but not vertically
	 */
	top_align = gtk_alignment_new(0, 0, 1, 0);
	top_vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(top_align), top_vbox);
	gtk_box_pack_start(GTK_BOX(main_vbox), top_align, FALSE, FALSE, 0);

	probe = gtk_frame_new("Run statistics");
	gtk_box_pack_start(GTK_BOX(main_vbox), probe, FALSE, FALSE, 3);
	probe_frame = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(probe), probe_frame);

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, FALSE, FALSE, 3);
	ui->eta.jobs = new_info_entry_in_frame(probe_box, "Running");
	ui->eta.read_bw = new_info_entry_in_frame_rgb(probe_box, "Read BW", GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	ui->eta.read_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_READ_R, GFIO_READ_G, GFIO_READ_B);
	ui->eta.write_bw = new_info_entry_in_frame_rgb(probe_box, "Write BW", GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	ui->eta.write_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_WRITE_R, GFIO_WRITE_G, GFIO_WRITE_B);
	ui->eta.trim_bw = new_info_entry_in_frame_rgb(probe_box, "Trim BW", GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);
	ui->eta.trim_iops = new_info_entry_in_frame_rgb(probe_box, "IOPS", GFIO_TRIM_R, GFIO_TRIM_G, GFIO_TRIM_B);

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
	 * Set up a drawing area and IOPS and bandwidth graphs
	 */
	ui->graphs.drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(ui->graphs.drawing_area),
		DRAWING_AREA_XDIM, DRAWING_AREA_YDIM);
	gtk_widget_modify_bg(ui->graphs.drawing_area, GTK_STATE_NORMAL, &gfio_color_lightyellow);
	g_signal_connect(G_OBJECT(ui->graphs.drawing_area), GFIO_DRAW_EVENT,
			G_CALLBACK(on_expose_drawing_area), &ui->graphs);
	g_signal_connect(G_OBJECT(ui->graphs.drawing_area), "configure_event",
			G_CALLBACK(on_config_drawing_area), &ui->graphs);
	scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
					GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrolled_window),
					ui->graphs.drawing_area);
	gtk_box_pack_start(GTK_BOX(main_vbox), scrolled_window,
			TRUE, TRUE, 0);

	setup_graphs(&ui->graphs);

	/*
	 * Set up alignments for widgets at the bottom of ui,
	 * align bottom left, expand horizontally but not vertically
	 */
	bottom_align = gtk_alignment_new(0, 1, 1, 0);
	ui->buttonbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(bottom_align), ui->buttonbox);
	gtk_box_pack_start(GTK_BOX(main_vbox), bottom_align, FALSE, FALSE, 0);

	/*
	 * Set up thread status progress bar
	 */
	ui->thread_status_pb = gtk_progress_bar_new();
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui->thread_status_pb), 0.0);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui->thread_status_pb), "No connections");
	gtk_container_add(GTK_CONTAINER(ui->buttonbox), ui->thread_status_pb);

	return main_vbox;
}

static gboolean notebook_switch_page(GtkNotebook *notebook, GtkWidget *widget,
				     guint page, gpointer data)

{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	if (!page) {
		set_job_menu_visible(ui, 0);
		set_view_results_visible(ui, 0);
		return TRUE;
	}

	set_job_menu_visible(ui, 1);
	ge = get_ge_from_page(ui, page, NULL);
	if (ge)
		update_button_states(ui, ge);

	return TRUE;
}

static gint compare_recent_items(GtkRecentInfo *a, GtkRecentInfo *b)
{
	time_t time_a = gtk_recent_info_get_visited(a);
	time_t time_b = gtk_recent_info_get_visited(b);

	return time_b - time_a;
}

static void add_recent_file_items(struct gui *ui)
{
	const gchar *gfio = g_get_application_name();
	GList *items, *item;
	int i = 0;

	if (ui->recent_ui_id) {
		gtk_ui_manager_remove_ui(ui->uimanager, ui->recent_ui_id);
		gtk_ui_manager_ensure_update(ui->uimanager);
	}
	ui->recent_ui_id = gtk_ui_manager_new_merge_id(ui->uimanager);

	if (ui->actiongroup) {
		gtk_ui_manager_remove_action_group(ui->uimanager, ui->actiongroup);
		g_object_unref(ui->actiongroup);
	}
	ui->actiongroup = gtk_action_group_new("RecentFileActions");

	gtk_ui_manager_insert_action_group(ui->uimanager, ui->actiongroup, -1);

	items = gtk_recent_manager_get_items(ui->recentmanager);
	items = g_list_sort(items, (GCompareFunc) compare_recent_items);

	for (item = items; item && item->data; item = g_list_next(item)) {
		GtkRecentInfo *info = (GtkRecentInfo *) item->data;
		gchar *action_name;
		const gchar *label;
		GtkAction *action;

		if (!gtk_recent_info_has_application(info, gfio))
			continue;

		/*
		 * We only support local files for now
		 */
		if (!gtk_recent_info_is_local(info) || !gtk_recent_info_exists(info))
			continue;

		action_name = g_strdup_printf("RecentFile%u", i++);
		label = gtk_recent_info_get_display_name(info);

		action = g_object_new(GTK_TYPE_ACTION,
					"name", action_name,
					"label", label, NULL);

		g_object_set_data_full(G_OBJECT(action), "gtk-recent-info",
					gtk_recent_info_ref(info),
					(GDestroyNotify) gtk_recent_info_unref);


		g_signal_connect(action, "activate", G_CALLBACK(recent_open), ui);

		gtk_action_group_add_action(ui->actiongroup, action);
		g_object_unref(action);

		gtk_ui_manager_add_ui(ui->uimanager, ui->recent_ui_id,
					"/MainMenu/FileMenu/FileRecentFiles",
					label, action_name,
					GTK_UI_MANAGER_MENUITEM, FALSE);

		g_free(action_name);

		if (i == 8)
			break;
	}

	g_list_foreach(items, (GFunc) gtk_recent_info_unref, NULL);
	g_list_free(items);
}

static void drag_and_drop_received(GtkWidget *widget, GdkDragContext *ctx,
				   gint x, gint y, GtkSelectionData *seldata,
				   guint info, guint time, gpointer *data)
{
	struct gui *ui = (struct gui *) data;
	gchar **uris;
	GtkWidget *source;

	source = gtk_drag_get_source_widget(ctx);
	if (source && widget == gtk_widget_get_toplevel(source)) {
		gtk_drag_finish(ctx, FALSE, FALSE, time);
		return;
	}

	uris = gtk_selection_data_get_uris(seldata);
	if (!uris) {
		gtk_drag_finish(ctx, FALSE, FALSE, time);
		return;
	}

	if (uris[0])
		do_file_open_with_tab(ui, uris[0]);

	gtk_drag_finish(ctx, TRUE, FALSE, time);
	g_strfreev(uris);
}

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	GtkSettings *settings;
	GtkWidget *vbox;

	/* Magical g*thread incantation, you just need this thread stuff.
	 * Without it, the update that happens in gfio_update_thread_status
	 * doesn't really happen in a timely fashion, you need expose events
	 */
#if !GTK_CHECK_VERSION(2, 24, 0)
	if (!g_thread_supported())
		g_thread_init(NULL);
#endif

	gdk_threads_init();

	gtk_init(argc, argv);
	settings = gtk_settings_get_default();
	gtk_settings_set_long_property(settings, "gtk_tooltip_timeout", 10, "gfio setting");
	g_type_init();
	gdk_color_parse("#fffff4", &gfio_color_lightyellow);
	gdk_color_parse("white", &gfio_color_white);

	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 1024, 768);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK(quit_clicked), ui);
	g_signal_connect(ui->window, "destroy", G_CALLBACK(quit_clicked), ui);

	ui->vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ui->window), ui->vbox);

	ui->uimanager = gtk_ui_manager_new();
	ui->menu = get_menubar_menu(ui->window, ui->uimanager, ui);
	gfio_ui_setup(settings, ui->menu, ui->vbox, ui->uimanager);

	ui->recentmanager = gtk_recent_manager_get_default();
	add_recent_file_items(ui);

	ui->notebook = gtk_notebook_new();
	g_signal_connect(ui->notebook, "switch-page", G_CALLBACK(notebook_switch_page), ui);
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(ui->notebook), 1);
	gtk_notebook_popup_enable(GTK_NOTEBOOK(ui->notebook));
	gtk_container_add(GTK_CONTAINER(ui->vbox), ui->notebook);

	vbox = new_main_page(ui);
	gtk_drag_dest_set(GTK_WIDGET(ui->window), GTK_DEST_DEFAULT_ALL, NULL, 1, GDK_ACTION_COPY);
	gtk_drag_dest_add_uri_targets(GTK_WIDGET(ui->window));
	g_signal_connect(ui->window, "drag-data-received", G_CALLBACK(drag_and_drop_received), ui);

	gtk_notebook_append_page(GTK_NOTEBOOK(ui->notebook), vbox, gtk_label_new("Main"));

	gfio_ui_setup_log(ui);

	gtk_widget_show_all(ui->window);
}

int main(int argc, char *argv[], char *envp[])
{
	if (initialize_fio(envp))
		return 1;
	if (fio_init_options())
		return 1;

	gopt_init();

	memset(&main_ui, 0, sizeof(main_ui));
	main_ui.ge_hash = g_hash_table_new(g_int_hash, g_int_equal);

	init_ui(&argc, &argv, &main_ui);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();

	g_hash_table_destroy(main_ui.ge_hash);

	gopt_exit();
	return 0;
}
