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
#include "graph.h"

#define GFIO_MIME	"text/fio"

static int gfio_server_running;
static const char *gfio_graph_font;
static unsigned int gfio_graph_limit = 100;

static void view_log(GtkWidget *w, gpointer data);

#define ARRAYSIZE(x) (sizeof((x)) / (sizeof((x)[0])))

typedef void (*clickfunction)(GtkWidget *widget, gpointer data);

static void connect_clicked(GtkWidget *widget, gpointer data);
static void start_job_clicked(GtkWidget *widget, gpointer data);
static void send_clicked(GtkWidget *widget, gpointer data);

static struct button_spec {
	const char *buttontext;
	clickfunction f;
	const char *tooltiptext;
	const int start_insensitive;
} buttonspeclist[] = {
#define CONNECT_BUTTON 0
#define SEND_BUTTON 1
#define START_JOB_BUTTON 2
	{ "Connect", connect_clicked, "Connect to host", 0 },
	{ "Send", send_clicked, "Send job description to host", 1 },
	{ "Start Job", start_job_clicked,
		"Start the current job on the server", 1 },
};

struct probe_widget {
	GtkWidget *hostname;
	GtkWidget *os;
	GtkWidget *arch;
	GtkWidget *fio_ver;
};

struct multitext_widget {
	GtkWidget *entry;
	char **text;
	unsigned int cur_text;
	unsigned int max_text;
};

struct eta_widget {
	GtkWidget *names;
	struct multitext_widget iotype;
	struct multitext_widget ioengine;
	struct multitext_widget iodepth;
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

struct gfio_graphs {
#define DRAWING_AREA_XDIM 1000
#define DRAWING_AREA_YDIM 400
	GtkWidget *drawing_area;
	struct graph *iops_graph;
	struct graph *bandwidth_graph;
};

/*
 * Main window widgets and data
 */
struct gui {
	GtkUIManager *uimanager;
	GtkRecentManager *recentmanager;
	GtkActionGroup *actiongroup;
	guint recent_ui_id;
	GtkWidget *menu;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *thread_status_pb;
	GtkWidget *buttonbox;
	GtkWidget *notebook;
	GtkWidget *error_info_bar;
	GtkWidget *error_label;
	GtkListStore *log_model;
	GtkWidget *log_tree;
	GtkWidget *log_view;
	struct gfio_graphs graphs;
	struct probe_widget probe;
	struct eta_widget eta;
	pthread_t server_t;

	pthread_t t;
	int handler_running;

	struct flist_head list;
} main_ui;

enum {
	GE_STATE_NEW = 1,
	GE_STATE_CONNECTED,
	GE_STATE_JOB_SENT,
	GE_STATE_JOB_STARTED,
	GE_STATE_JOB_RUNNING,
	GE_STATE_JOB_DONE,
};

/*
 * Notebook entry
 */
struct gui_entry {
	struct flist_head list;
	struct gui *ui;

	GtkWidget *vbox;
	GtkWidget *job_notebook;
	GtkWidget *thread_status_pb;
	GtkWidget *buttonbox;
	GtkWidget *button[ARRAYSIZE(buttonspeclist)];
	GtkWidget *notebook;
	GtkWidget *error_info_bar;
	GtkWidget *error_label;
	GtkWidget *results_notebook;
	GtkWidget *results_window;
	GtkListStore *log_model;
	GtkWidget *log_tree;
	GtkWidget *log_view;
	struct gfio_graphs graphs;
	struct probe_widget probe;
	struct eta_widget eta;
	GtkWidget *page_label;
	gint page_num;
	unsigned int state;

	struct gfio_client *client;
	int nr_job_files;
	char **job_files;
};

struct gfio_client {
	struct gui_entry *ge;
	struct fio_client *client;
	GtkWidget *results_widget;
	GtkWidget *disk_util_frame;
	GtkWidget *err_entry;
	unsigned int job_added;
	struct thread_options o;
};

static void gfio_update_thread_status(struct gui_entry *ge, char *status_message, double perc);
static void gfio_update_thread_status_all(char *status_message, double perc);
void report_error(GError *error);

static struct graph *setup_iops_graph(void)
{
	struct graph *g;

	g = graph_new(DRAWING_AREA_XDIM / 2.0, DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(g, "IOPS (IOs/sec)");
	graph_x_title(g, "Time (secs)");
	graph_add_label(g, "Read IOPS");
	graph_add_label(g, "Write IOPS");
	graph_set_color(g, "Read IOPS", 0.13, 0.54, 0.13);
	graph_set_color(g, "Write IOPS", 1.0, 0.0, 0.0);
	line_graph_set_data_count_limit(g, gfio_graph_limit);
	graph_add_extra_space(g, 0.0, 0.0, 0.0, 0.0);
	return g;
}

static struct graph *setup_bandwidth_graph(void)
{
	struct graph *g;

	g = graph_new(DRAWING_AREA_XDIM / 2.0, DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(g, "Bandwidth (bytes/sec)");
	graph_x_title(g, "Time (secs)");
	graph_add_label(g, "Read Bandwidth");
	graph_add_label(g, "Write Bandwidth");
	graph_set_color(g, "Read Bandwidth", 0.13, 0.54, 0.13);
	graph_set_color(g, "Write Bandwidth", 1.0, 0.0, 0.0);
	graph_set_base_offset(g, 1);
	line_graph_set_data_count_limit(g, 100);
	graph_add_extra_space(g, 0.0, 0.0, 0.0, 0.0);
	return g;
}

static void setup_graphs(struct gfio_graphs *g)
{
	g->iops_graph = setup_iops_graph();
	g->bandwidth_graph = setup_bandwidth_graph();
}

static void multitext_add_entry(struct multitext_widget *mt, const char *text)
{
	mt->text = realloc(mt->text, (mt->max_text + 1) * sizeof(char *));
	mt->text[mt->max_text] = strdup(text);
	mt->max_text++;
}

static void multitext_set_entry(struct multitext_widget *mt, unsigned int index)
{
	if (index >= mt->max_text)
		return;
	if (!mt->text || !mt->text[index])
		return;

	mt->cur_text = index;
	gtk_entry_set_text(GTK_ENTRY(mt->entry), mt->text[index]);
}

static void multitext_update_entry(struct multitext_widget *mt,
				   unsigned int index, const char *text)
{
	if (!mt->text)
		return;

	if (mt->text[index])
		free(mt->text[index]);

	mt->text[index] = strdup(text);
	if (mt->cur_text == index)
		gtk_entry_set_text(GTK_ENTRY(mt->entry), mt->text[index]);
}

static void multitext_free(struct multitext_widget *mt)
{
	int i;

	gtk_entry_set_text(GTK_ENTRY(mt->entry), "");

	for (i = 0; i < mt->max_text; i++) {
		if (mt->text[i])
			free(mt->text[i]);
	}

	free(mt->text);
	mt->cur_text = -1;
	mt->max_text = 0;
}

static void clear_ge_ui_info(struct gui_entry *ge)
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
	multitext_update_entry(&ge->eta.ioengine, 0, "");
	multitext_update_entry(&ge->eta.iodepth, 0, "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.jobs), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.files), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.read_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.read_iops), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.write_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.write_iops), "");
}

static GtkWidget *new_combo_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_combo_box_new_text();
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

	return entry;
}

static GtkWidget *new_info_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_entry_new();
	gtk_entry_set_editable(GTK_ENTRY(entry), 0);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

	return entry;
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

static void label_set_int_value(GtkWidget *entry, unsigned int val)
{
	char tmp[80];

	sprintf(tmp, "%u", val);
	gtk_label_set_text(GTK_LABEL(entry), tmp);
}

static void entry_set_int_value(GtkWidget *entry, unsigned int val)
{
	char tmp[80];

	sprintf(tmp, "%u", val);
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);
}

static void show_info_dialog(struct gui *ui, const char *title,
			     const char *message)
{
	GtkWidget *dialog, *content, *label;

	dialog = gtk_dialog_new_with_buttons(title, GTK_WINDOW(ui->window),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_OK, NULL);

	content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	label = gtk_label_new(message);
	gtk_container_add(GTK_CONTAINER(content), label);
	gtk_widget_show_all(dialog);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
	gtk_dialog_run(GTK_DIALOG(dialog));
	gtk_widget_destroy(dialog);
}

/*
 * Update sensitivity of job buttons and job menu items, based on the
 * state of the client.
 */
static void update_button_states(struct gui *ui, struct gui_entry *ge)
{
	unsigned int connect_state, send_state, start_state, edit_state;
	const char *connect_str = NULL;
	GtkWidget *w;

	switch (ge->state) {
	default: {
		char tmp[80];

		sprintf(tmp, "Bad client state: %u\n", ge->state);
		show_info_dialog(ui, "Error", tmp);
		/* fall through to new state */
		}

	case GE_STATE_NEW:
		connect_state = 1;
		edit_state = 0;
		connect_str = "Connect";
		send_state = 0;
		start_state = 0;
		break;
	case GE_STATE_CONNECTED:
		connect_state = 1;
		edit_state = 0;
		connect_str = "Disconnect";
		send_state = 1;
		start_state = 0;
		break;
	case GE_STATE_JOB_SENT:
		connect_state = 1;
		edit_state = 0;
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

	gtk_widget_set_sensitive(ge->button[CONNECT_BUTTON], connect_state);
	gtk_widget_set_sensitive(ge->button[SEND_BUTTON], send_state);
	gtk_widget_set_sensitive(ge->button[START_JOB_BUTTON], start_state);
	gtk_button_set_label(GTK_BUTTON(ge->button[CONNECT_BUTTON]), connect_str);

	/*
	 * So the below doesn't work at all, how to set those menu items
	 * invisibible...
	 */
	w = gtk_ui_manager_get_widget(ui->uimanager, "/MainMenu/JobMenu/Connect");
	gtk_widget_set_sensitive(w, connect_state);
	gtk_menu_item_set_label(GTK_MENU_ITEM(w), connect_str);

	w = gtk_ui_manager_get_widget(ui->uimanager, "/MainMenu/JobMenu/Edit job");
	gtk_widget_set_sensitive(w, edit_state);

	w = gtk_ui_manager_get_widget(ui->uimanager, "/MainMenu/JobMenu/Send job");
	gtk_widget_set_sensitive(w, send_state);

	w = gtk_ui_manager_get_widget(ui->uimanager, "/MainMenu/JobMenu/Start job");
	gtk_widget_set_sensitive(w, start_state);
}

static void gfio_set_state(struct gui_entry *ge, unsigned int state)
{
	ge->state = state;
	update_button_states(ge->ui, ge);
}

#define ALIGN_LEFT 1
#define ALIGN_RIGHT 2
#define INVISIBLE 4
#define UNSORTABLE 8

GtkTreeViewColumn *tree_view_column(GtkWidget *tree_view, int index, const char *title, unsigned int flags)
{
	GtkCellRenderer *renderer;
	GtkTreeViewColumn *col;
	double xalign = 0.0; /* left as default */
	PangoAlignment align;
	gboolean visible;

	align = (flags & ALIGN_LEFT) ? PANGO_ALIGN_LEFT :
		(flags & ALIGN_RIGHT) ? PANGO_ALIGN_RIGHT :
		PANGO_ALIGN_CENTER;
	visible = !(flags & INVISIBLE);

	renderer = gtk_cell_renderer_text_new();
	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, title);
	if (!(flags & UNSORTABLE))
		gtk_tree_view_column_set_sort_column_id(col, index);
	gtk_tree_view_column_set_resizable(col, TRUE);
	gtk_tree_view_column_pack_start(col, renderer, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", index);
	gtk_object_set(GTK_OBJECT(renderer), "alignment", align, NULL);
	switch (align) {
	case PANGO_ALIGN_LEFT:
		xalign = 0.0;
		break;
	case PANGO_ALIGN_CENTER:
		xalign = 0.5;
		break;
	case PANGO_ALIGN_RIGHT:
		xalign = 1.0;
		break;
	}
	gtk_cell_renderer_set_alignment(GTK_CELL_RENDERER(renderer), xalign, 0.5);
	gtk_tree_view_column_set_visible(col, visible);
	gtk_tree_view_append_column(GTK_TREE_VIEW(tree_view), col);
	return col;
}

static void gfio_ui_setup_log(struct gui *ui)
{
	GtkTreeSelection *selection;
	GtkListStore *model;
	GtkWidget *tree_view;

	model = gtk_list_store_new(4, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INT, G_TYPE_STRING);

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

static GtkWidget *gfio_output_clat_percentiles(unsigned int *ovals,
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
	int i;

	for (i = 0; i < len; i++)
		types[i] = G_TYPE_INT;

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
		if (scale)
			ovals[i] = (ovals[i] + 999) / 1000;
		gtk_list_store_set(model, &iter, i, ovals[i], -1);
	}

	return tree_view;
}

static void gfio_show_clat_percentiles(GtkWidget *vbox, struct thread_stat *ts,
				       int ddir)
{
	unsigned int *io_u_plat = ts->io_u_plat[ddir];
	unsigned long nr = ts->clat_stat[ddir].samples;
	fio_fp64_t *plist = ts->percentile_list;
	unsigned int *ovals, len, minv, maxv, scale_down;
	const char *base;
	GtkWidget *tree_view, *frame, *hbox;
	char tmp[64];

	len = calc_clat_percentiles(io_u_plat, nr, plist, &ovals, &maxv, &minv);
	if (!len)
		goto out;

	/*
	 * We default to usecs, but if the value range is such that we
	 * should scale down to msecs, do that.
	 */
	if (minv > 2000 && maxv > 99999) {
		scale_down = 1;
		base = "msec";
	} else {
		scale_down = 0;
		base = "usec";
	}

	tree_view = gfio_output_clat_percentiles(ovals, plist, len, base, scale_down);

	sprintf(tmp, "Completion percentiles (%s)", base);
	frame = gtk_frame_new(tmp);
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), hbox);

	gtk_box_pack_start(GTK_BOX(hbox), tree_view, TRUE, FALSE, 3);
out:
	if (ovals)
		free(ovals);
}

static void gfio_show_lat(GtkWidget *vbox, const char *name, unsigned long min,
			  unsigned long max, double mean, double dev)
{
	const char *base = "(usec)";
	GtkWidget *hbox, *label, *frame;
	char *minp, *maxp;
	char tmp[64];

	if (!usec_to_msec(&min, &max, &mean, &dev))
		base = "(msec)";

	minp = num2str(min, 6, 1, 0);
	maxp = num2str(max, 6, 1, 0);

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

#define GFIO_CLAT	1
#define GFIO_SLAT	2
#define GFIO_LAT	4

static void gfio_show_ddir_status(GtkWidget *mbox, struct group_run_stats *rs,
				  struct thread_stat *ts, int ddir)
{
	const char *ddir_label[2] = { "Read", "Write" };
	GtkWidget *frame, *label, *box, *vbox, *main_vbox;
	unsigned long min[3], max[3], runt;
	unsigned long long bw, iops;
	unsigned int flags = 0;
	double mean[3], dev[3];
	char *io_p, *bw_p, *iops_p;
	int i2p;

	if (!ts->runtime[ddir])
		return;

	i2p = is_power_of_2(rs->kb_base);
	runt = ts->runtime[ddir];

	bw = (1000 * ts->io_bytes[ddir]) / runt;
	io_p = num2str(ts->io_bytes[ddir], 6, 1, i2p);
	bw_p = num2str(bw, 6, 1, i2p);

	iops = (1000 * (uint64_t)ts->total_io_u[ddir]) / runt;
	iops_p = num2str(iops, 6, 1, 0);

	box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(mbox), box, TRUE, FALSE, 3);

	frame = gtk_frame_new(ddir_label[ddir]);
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 5);

	main_vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), main_vbox);

	box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(main_vbox), box, TRUE, FALSE, 3);

	label = new_info_label_in_frame(box, "IO");
	gtk_label_set_text(GTK_LABEL(label), io_p);
	label = new_info_label_in_frame(box, "Bandwidth");
	gtk_label_set_text(GTK_LABEL(label), bw_p);
	label = new_info_label_in_frame(box, "IOPS");
	gtk_label_set_text(GTK_LABEL(label), iops_p);
	label = new_info_label_in_frame(box, "Runtime (msec)");
	label_set_int_value(label, ts->runtime[ddir]);

	if (calc_lat(&ts->bw_stat[ddir], &min[0], &max[0], &mean[0], &dev[0])) {
		double p_of_agg = 100.0;
		const char *bw_str = "KB";
		char tmp[32];

		if (rs->agg[ddir]) {
			p_of_agg = mean[0] * 100 / (double) rs->agg[ddir];
			if (p_of_agg > 100.0)
				p_of_agg = 100.0;
		}

		if (mean[0] > 999999.9) {
			min[0] /= 1000.0;
			max[0] /= 1000.0;
			mean[0] /= 1000.0;
			dev[0] /= 1000.0;
			bw_str = "MB";
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

	if (flags) {
		frame = gtk_frame_new("Latency");
		gtk_box_pack_start(GTK_BOX(main_vbox), frame, FALSE, FALSE, 5);

		vbox = gtk_vbox_new(FALSE, 3);
		gtk_container_add(GTK_CONTAINER(frame), vbox);

		if (flags & GFIO_SLAT)
			gfio_show_lat(vbox, "Submission latency", min[0], max[0], mean[0], dev[0]);
		if (flags & GFIO_CLAT)
			gfio_show_lat(vbox, "Completion latency", min[1], max[1], mean[1], dev[1]);
		if (flags & GFIO_LAT)
			gfio_show_lat(vbox, "Total latency", min[2], max[2], mean[2], dev[2]);
	}

	if (ts->clat_percentiles)
		gfio_show_clat_percentiles(main_vbox, ts, ddir);


	free(io_p);
	free(bw_p);
	free(iops_p);
}

static GtkWidget *gfio_output_lat_buckets(double *lat, unsigned int num,
					  const char **labels)
{
	GtkWidget *tree_view;
	GtkTreeSelection *selection;
	GtkListStore *model;
	GtkTreeIter iter;
	GType *types;
	int i, skipped;

	/*
	 * Check if all are empty, in which case don't bother
	 */
	for (i = 0, skipped = 0; i < num; i++)
		if (lat[i] <= 0.0)
			skipped++;

	if (skipped == num)
		return NULL;

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

static void gfio_show_latency_buckets(GtkWidget *vbox, struct thread_stat *ts)
{
	GtkWidget *box, *frame, *tree_view;
	double io_u_lat_u[FIO_IO_U_LAT_U_NR];
	double io_u_lat_m[FIO_IO_U_LAT_M_NR];
	const char *uranges[] = { "2", "4", "10", "20", "50", "100",
				  "250", "500", "750", "1000", };
	const char *mranges[] = { "2", "4", "10", "20", "50", "100",
				  "250", "500", "750", "1000", "2000",
				  ">= 2000", };

	stat_calc_lat_u(ts, io_u_lat_u);
	stat_calc_lat_m(ts, io_u_lat_m);

	tree_view = gfio_output_lat_buckets(io_u_lat_u, FIO_IO_U_LAT_U_NR, uranges);
	if (tree_view) {
		frame = gtk_frame_new("Latency buckets (usec)");
		gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

		box = gtk_hbox_new(FALSE, 3);
		gtk_container_add(GTK_CONTAINER(frame), box);
		gtk_box_pack_start(GTK_BOX(box), tree_view, TRUE, FALSE, 3);
	}

	tree_view = gfio_output_lat_buckets(io_u_lat_m, FIO_IO_U_LAT_M_NR, mranges);
	if (tree_view) {
		frame = gtk_frame_new("Latency buckets (msec)");
		gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

		box = gtk_hbox_new(FALSE, 3);
		gtk_container_add(GTK_CONTAINER(frame), box);
		gtk_box_pack_start(GTK_BOX(box), tree_view, TRUE, FALSE, 3);
	}
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

static void gfio_add_total_depths_tree(GtkListStore *model,
				       struct thread_stat *ts, unsigned int len)
{
	double io_u_dist[FIO_IO_U_MAP_NR];
	GtkTreeIter iter;
	/* Bits 1-6, and 8 */
	const int add_mask = 0x17e;
	int i, j;

	stat_calc_dist(ts->io_u_map, ts_total_io_u(ts), io_u_dist);

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

static void gfio_show_io_depths(GtkWidget *vbox, struct thread_stat *ts)
{
	GtkWidget *frame, *box, *tree_view;
	GtkTreeSelection *selection;
	GtkListStore *model;
	GType types[FIO_IO_U_MAP_NR + 1];
	int i;
#define NR_LABELS	10
	const char *labels[NR_LABELS] = { "Depth", "0", "1", "2", "4", "8", "16", "32", "64", ">= 64" };

	frame = gtk_frame_new("IO depths");
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 5);

	box = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), box);

	for (i = 0; i < NR_LABELS; i++)
		types[i] = G_TYPE_STRING;

	model = gtk_list_store_newv(NR_LABELS, types);

	tree_view = gtk_tree_view_new_with_model(GTK_TREE_MODEL(model));
	gtk_widget_set_can_focus(tree_view, FALSE);

	g_object_set(G_OBJECT(tree_view), "headers-visible", TRUE,
		"enable-grid-lines", GTK_TREE_VIEW_GRID_LINES_BOTH, NULL);

	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view));
	gtk_tree_selection_set_mode(GTK_TREE_SELECTION(selection), GTK_SELECTION_BROWSE);

	for (i = 0; i < NR_LABELS; i++)
		tree_view_column(tree_view, i, labels[i], ALIGN_RIGHT | UNSORTABLE);

	gfio_add_total_depths_tree(model, ts, NR_LABELS);
	gfio_add_sc_depths_tree(model, ts, NR_LABELS, 1);
	gfio_add_sc_depths_tree(model, ts, NR_LABELS, 0);

	gtk_box_pack_start(GTK_BOX(box), tree_view, TRUE, FALSE, 3);
}

static gboolean results_window_delete(GtkWidget *w, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	gtk_widget_destroy(w);
	ge->results_window = NULL;
	ge->results_notebook = NULL;
	return TRUE;
}

static GtkWidget *get_results_window(struct gui_entry *ge)
{
	GtkWidget *win, *notebook;

	if (ge->results_window)
		return ge->results_notebook;

	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "Results");
	gtk_window_set_default_size(GTK_WINDOW(win), 1024, 768);
	g_signal_connect(win, "delete-event", G_CALLBACK(results_window_delete), ge);
	g_signal_connect(win, "destroy", G_CALLBACK(results_window_delete), ge);

	notebook = gtk_notebook_new();
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), 1);
	gtk_notebook_popup_enable(GTK_NOTEBOOK(notebook));
	gtk_container_add(GTK_CONTAINER(win), notebook);

	ge->results_window = win;
	ge->results_notebook = notebook;
	return ge->results_notebook;
}

static void gfio_display_ts(struct fio_client *client, struct thread_stat *ts,
			    struct group_run_stats *rs)
{
	GtkWidget *res_win, *box, *vbox, *entry, *scroll;
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();

	res_win = get_results_window(gc->ge);

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	vbox = gtk_vbox_new(FALSE, 3);

	box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), box, TRUE, FALSE, 5);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), vbox);

	gtk_notebook_append_page(GTK_NOTEBOOK(res_win), scroll, gtk_label_new(ts->name));

	gc->results_widget = vbox;

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

	if (ts->io_bytes[DDIR_READ])
		gfio_show_ddir_status(vbox, rs, ts, DDIR_READ);
	if (ts->io_bytes[DDIR_WRITE])
		gfio_show_ddir_status(vbox, rs, ts, DDIR_WRITE);

	gfio_show_latency_buckets(vbox, ts);
	gfio_show_cpu_usage(vbox, ts);
	gfio_show_io_depths(vbox, ts);

	gtk_widget_show_all(gc->ge->results_window);
	gdk_threads_leave();
}

static void gfio_text_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_text_pdu *p = (struct cmd_text_pdu *) cmd->payload;
	struct gui *ui = &main_ui;
	GtkTreeIter iter;
	struct tm *tm;
	time_t sec;
	char tmp[64], timebuf[80];

	sec = p->log_sec;
	tm = localtime(&sec);
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm);
	sprintf(timebuf, "%s.%03ld", tmp, p->log_usec / 1000);

	gdk_threads_enter();

	gtk_list_store_append(ui->log_model, &iter);
	gtk_list_store_set(ui->log_model, &iter, 0, timebuf, -1);
	gtk_list_store_set(ui->log_model, &iter, 1, client->hostname, -1);
	gtk_list_store_set(ui->log_model, &iter, 2, p->level, -1);
	gtk_list_store_set(ui->log_model, &iter, 3, p->buf, -1);

	if (p->level == FIO_LOG_ERR)
		view_log(NULL, (gpointer) ui);

	gdk_threads_leave();
}

static void gfio_disk_util_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_du_pdu *p = (struct cmd_du_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	GtkWidget *box, *frame, *entry, *vbox;
	double util;
	char tmp[16];

	gdk_threads_enter();

	if (!gc->results_widget)
		goto out;

	if (!gc->disk_util_frame) {
		gc->disk_util_frame = gtk_frame_new("Disk utilization");
		gtk_box_pack_start(GTK_BOX(gc->results_widget), gc->disk_util_frame, FALSE, FALSE, 5);
	}

	vbox = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(gc->disk_util_frame), vbox);

	frame = gtk_frame_new((char *) p->dus.name);
	gtk_box_pack_start(GTK_BOX(vbox), frame, FALSE, FALSE, 2);

	box = gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), box);

	frame = gtk_frame_new("Read");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IOs");
	entry_set_int_value(entry, p->dus.ios[0]);
	entry = new_info_entry_in_frame(vbox, "Merges");
	entry_set_int_value(entry, p->dus.merges[0]);
	entry = new_info_entry_in_frame(vbox, "Sectors");
	entry_set_int_value(entry, p->dus.sectors[0]);
	entry = new_info_entry_in_frame(vbox, "Ticks");
	entry_set_int_value(entry, p->dus.ticks[0]);

	frame = gtk_frame_new("Write");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IOs");
	entry_set_int_value(entry, p->dus.ios[1]);
	entry = new_info_entry_in_frame(vbox, "Merges");
	entry_set_int_value(entry, p->dus.merges[1]);
	entry = new_info_entry_in_frame(vbox, "Sectors");
	entry_set_int_value(entry, p->dus.sectors[1]);
	entry = new_info_entry_in_frame(vbox, "Ticks");
	entry_set_int_value(entry, p->dus.ticks[1]);

	frame = gtk_frame_new("Shared");
	gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 2);
	vbox = gtk_hbox_new(TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), vbox);
	entry = new_info_entry_in_frame(vbox, "IO ticks");
	entry_set_int_value(entry, p->dus.io_ticks);
	entry = new_info_entry_in_frame(vbox, "Time in queue");
	entry_set_int_value(entry, p->dus.time_in_queue);

	util = 0.0;
	if (p->dus.msec)
		util = (double) 100 * p->dus.io_ticks / (double) p->dus.msec;
	if (util > 100.0)
		util = 100.0;

	sprintf(tmp, "%3.2f%%", util);
	entry = new_info_entry_in_frame(vbox, "Disk utilization");
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);

	gtk_widget_show_all(gc->results_widget);
out:
	gdk_threads_leave();
}

extern int sum_stat_clients;
extern struct thread_stat client_ts;
extern struct group_run_stats client_gs;

static int sum_stat_nr;

static void gfio_thread_status_op(struct fio_client *client,
				  struct fio_net_cmd *cmd)
{
	struct cmd_ts_pdu *p = (struct cmd_ts_pdu *) cmd->payload;

	gfio_display_ts(client, &p->ts, &p->rs);

	if (sum_stat_clients == 1)
		return;

	sum_thread_stats(&client_ts, &p->ts, sum_stat_nr);
	sum_group_stats(&client_gs, &p->rs);

	client_ts.members++;
	client_ts.groupid = p->ts.groupid;

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

static gint on_config_drawing_area(GtkWidget *w, GdkEventConfigure *event,
				   gpointer data)
{
	struct gfio_graphs *g = data;

	graph_set_size(g->iops_graph, w->allocation.width / 2.0, w->allocation.height);
	graph_set_position(g->iops_graph, w->allocation.width / 2.0, 0.0);
	graph_set_size(g->bandwidth_graph, w->allocation.width / 2.0, w->allocation.height);
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

	cr = gdk_cairo_create(w->window);

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

#if 0
	if (je->m_rate[0] || je->m_rate[1] || je->t_rate[0] || je->t_rate[1]) {
	if (je->m_rate || je->t_rate) {
		char *tr, *mr;

		mr = num2str(je->m_rate, 4, 0, i2p);
		tr = num2str(je->t_rate, 4, 0, i2p);
		gtk_entry_set_text(GTK_ENTRY(ge->eta);
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops || je->t_iops)
		p += sprintf(p, ", CR=%d/%d IOPS", je->t_iops, je->m_iops);

	gtk_entry_set_text(GTK_ENTRY(ge->eta.cr_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.cr_iops), "---");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.cw_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ge->eta.cw_iops), "---");
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

		gtk_entry_set_text(GTK_ENTRY(ge->eta.read_bw), rate_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.read_iops), iops_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.write_bw), rate_str[1]);
		gtk_entry_set_text(GTK_ENTRY(ge->eta.write_iops), iops_str[1]);

		graph_add_xy_data(ge->graphs.iops_graph, "Read IOPS", je->elapsed_sec, je->iops[0], iops_str[0]);
		graph_add_xy_data(ge->graphs.iops_graph, "Write IOPS", je->elapsed_sec, je->iops[1], iops_str[1]);
		graph_add_xy_data(ge->graphs.bandwidth_graph, "Read Bandwidth", je->elapsed_sec, je->rate[0], rate_str[0]);
		graph_add_xy_data(ge->graphs.bandwidth_graph, "Write Bandwidth", je->elapsed_sec, je->rate[1], rate_str[1]);

		free(rate_str[0]);
		free(rate_str[1]);
		free(iops_str[0]);
		free(iops_str[1]);
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
	int i2p = 0;

	gdk_threads_enter();

	eta_str[0] = '\0';
	output[0] = '\0';

	if (je->eta_sec != INT_MAX && je->elapsed_sec) {
		perc = (double) je->elapsed_sec / (double) (je->elapsed_sec + je->eta_sec);
		eta_to_str(eta_str, je->eta_sec);
	}

#if 0
	if (je->m_rate[0] || je->m_rate[1] || je->t_rate[0] || je->t_rate[1]) {
	if (je->m_rate || je->t_rate) {
		char *tr, *mr;

		mr = num2str(je->m_rate, 4, 0, i2p);
		tr = num2str(je->t_rate, 4, 0, i2p);
		gtk_entry_set_text(GTK_ENTRY(ui->eta);
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops || je->t_iops)
		p += sprintf(p, ", CR=%d/%d IOPS", je->t_iops, je->m_iops);

	gtk_entry_set_text(GTK_ENTRY(ui->eta.cr_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.cr_iops), "---");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.cw_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.cw_iops), "---");
#endif

	entry_set_int_value(ui->eta.jobs, je->nr_running);

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

		gtk_entry_set_text(GTK_ENTRY(ui->eta.read_bw), rate_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.read_iops), iops_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.write_bw), rate_str[1]);
		gtk_entry_set_text(GTK_ENTRY(ui->eta.write_iops), iops_str[1]);

		graph_add_xy_data(ui->graphs.iops_graph, "Read IOPS", je->elapsed_sec, je->iops[0], iops_str[0]);
		graph_add_xy_data(ui->graphs.iops_graph, "Write IOPS", je->elapsed_sec, je->iops[1], iops_str[1]);
		graph_add_xy_data(ui->graphs.bandwidth_graph, "Read Bandwidth", je->elapsed_sec, je->rate[0], rate_str[0]);
		graph_add_xy_data(ui->graphs.bandwidth_graph, "Write Bandwidth", je->elapsed_sec, je->rate[1], rate_str[1]);

		free(rate_str[0]);
		free(rate_str[1]);
		free(iops_str[0]);
		free(iops_str[1]);
	}

	if (eta_str[0]) {
		char *dst = output + strlen(output);

		sprintf(dst, " - %s", eta_str);
	}
		
	gfio_update_thread_status_all(output, perc);
	gdk_threads_leave();
}

static void gfio_probe_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu *probe = (struct cmd_probe_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui_entry *ge = gc->ge;
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

	gdk_threads_enter();

	gtk_label_set_text(GTK_LABEL(ge->probe.hostname), (char *) probe->hostname);
	gtk_label_set_text(GTK_LABEL(ge->probe.os), os);
	gtk_label_set_text(GTK_LABEL(ge->probe.arch), arch);
	sprintf(buf, "%u.%u.%u", probe->fio_major, probe->fio_minor, probe->fio_patch);
	gtk_label_set_text(GTK_LABEL(ge->probe.fio_ver), buf);

	gfio_set_state(ge, GE_STATE_CONNECTED);

	gdk_threads_leave();
}

static void gfio_update_thread_status(struct gui_entry *ge,
				      char *status_message, double perc)
{
	static char message[100];
	const char *m = message;

	strncpy(message, status_message, sizeof(message) - 1);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ge->thread_status_pb), m);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ge->thread_status_pb), perc / 100.0);
	gtk_widget_queue_draw(main_ui.window);
}

static void gfio_update_thread_status_all(char *status_message, double perc)
{
	struct gui *ui = &main_ui;
	static char message[100];
	const char *m = message;

	strncpy(message, status_message, sizeof(message) - 1);
	gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ui->thread_status_pb), m);
	gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui->thread_status_pb), perc / 100.0);
	gtk_widget_queue_draw(ui->window);
}

static void gfio_quit_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();
	gfio_set_state(gc->ge, GE_STATE_NEW);
	gdk_threads_leave();
}

static void gfio_add_job_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_add_job_pdu *p = (struct cmd_add_job_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct thread_options *o = &gc->o;
	struct gui_entry *ge = gc->ge;
	char tmp[8];

	convert_thread_options_to_cpu(o, &p->top);

	gdk_threads_enter();

	gtk_label_set_text(GTK_LABEL(ge->page_label), (gchar *) o->name);

	gtk_combo_box_append_text(GTK_COMBO_BOX(ge->eta.names), (gchar *) o->name);
	gtk_combo_box_set_active(GTK_COMBO_BOX(ge->eta.names), 0);

	multitext_add_entry(&ge->eta.iotype, ddir_str(o->td_ddir));
	multitext_add_entry(&ge->eta.ioengine, (const char *) o->ioengine);

	sprintf(tmp, "%u", o->iodepth);
	multitext_add_entry(&ge->eta.iodepth, tmp);

	multitext_set_entry(&ge->eta.iotype, 0);
	multitext_set_entry(&ge->eta.ioengine, 0);
	multitext_set_entry(&ge->eta.iodepth, 0);

	gc->job_added++;

	gfio_set_state(ge, GE_STATE_JOB_SENT);

	gdk_threads_leave();
}

static void gfio_client_timed_out(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;
	char buf[256];

	gdk_threads_enter();

	gfio_set_state(gc->ge, GE_STATE_NEW);
	clear_ge_ui_info(gc->ge);

	sprintf(buf, "Client %s: timeout talking to server.\n", client->hostname);
	show_info_dialog(gc->ge->ui, "Network timeout", buf);

	gdk_threads_leave();
}

static void gfio_client_stop(struct fio_client *client, struct fio_net_cmd *cmd)
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
	.timed_out		= gfio_client_timed_out,
	.stop			= gfio_client_stop,
	.start			= gfio_client_start,
	.job_start		= gfio_client_job_start,
	.eta_msec		= FIO_CLIENT_DEF_ETA_MSEC,
	.stay_connected		= 1,
};

/*
 * FIXME: need more handling here
 */
static void ge_destroy(struct gui_entry *ge)
{
	struct gfio_client *gc = ge->client;

	if (gc && gc->client) {
		if (ge->state >= GE_STATE_CONNECTED)
			fio_client_terminate(gc->client);

		fio_put_client(gc->client);
	}

	flist_del(&ge->list);
	free(ge);
}

static void ge_widget_destroy(GtkWidget *w, gpointer data)
{
	struct gui_entry *ge = data;

	ge_destroy(ge);
}

static void gfio_quit(struct gui *ui)
{
	struct gui_entry *ge;

	while (!flist_empty(&ui->list)) {
		ge = flist_entry(ui->list.next, struct gui_entry, list);
		ge_destroy(ge);
	}

        gtk_main_quit();
}

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
	gfio_quit(data);
}

static void *job_thread(void *arg)
{
	struct gui *ui = arg;

	ui->handler_running = 1;
	fio_handle_clients(&gfio_client_ops);
	ui->handler_running = 0;
	return NULL;
}

static int send_job_files(struct gui_entry *ge)
{
	struct gfio_client *gc = ge->client;
	int i, ret = 0;

	for (i = 0; i < ge->nr_job_files; i++) {
		ret = fio_client_send_ini(gc->client, ge->job_files[i]);
		if (ret < 0) {
			GError *error;

			error = g_error_new(g_quark_from_string("fio"), 1, "Failed to send file %s: %s\n", ge->job_files[i], strerror(-ret));
			report_error(error);
			g_error_free(error);
			break;
		} else if (ret)
			break;

		free(ge->job_files[i]);
		ge->job_files[i] = NULL;
	}
	while (i < ge->nr_job_files) {
		free(ge->job_files[i]);
		ge->job_files[i] = NULL;
		i++;
	}

	free(ge->job_files);
	ge->job_files = NULL;
	ge->nr_job_files = 0;
	return ret;
}

static void *server_thread(void *arg)
{
	is_backend = 1;
	gfio_server_running = 1;
	fio_start_server(NULL);
	gfio_server_running = 0;
	return NULL;
}

static void gfio_start_server(void)
{
	struct gui *ui = &main_ui;

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

static void connect_clicked(GtkWidget *widget, gpointer data)
{
	struct gui_entry *ge = data;
	struct gfio_client *gc = ge->client;

	if (ge->state == GE_STATE_NEW) {
		int ret;

		if (!ge->nr_job_files)
			file_open(widget, ge->ui);
		if (!ge->nr_job_files)
			return;

		gtk_progress_bar_set_text(GTK_PROGRESS_BAR(ge->thread_status_pb), "No jobs running");
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ge->thread_status_pb), 0.0);
		ret = fio_client_connect(gc->client);
		if (!ret) {
			if (!ge->ui->handler_running)
				pthread_create(&ge->ui->t, NULL, job_thread, ge->ui);
			gfio_set_state(ge, GE_STATE_CONNECTED);
		} else {
			GError *error;

			error = g_error_new(g_quark_from_string("fio"), 1, "Failed to connect to %s: %s\n", ge->client->client->hostname, strerror(-ret));
			report_error(error);
			g_error_free(error);
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

	if (send_job_files(ge)) {
		GError *error;

		error = g_error_new(g_quark_from_string("fio"), 1, "Failed to send one or more job files for client %s", ge->client->client->hostname);
		report_error(error);
		g_error_free(error);

		gtk_widget_set_sensitive(ge->button[START_JOB_BUTTON], 1);
	}
}

static GtkWidget *add_button(GtkWidget *buttonbox,
			     struct button_spec *buttonspec, gpointer data)
{
	GtkWidget *button = gtk_button_new_with_label(buttonspec->buttontext);

	g_signal_connect(button, "clicked", G_CALLBACK(buttonspec->f), data);
	gtk_box_pack_start(GTK_BOX(buttonbox), button, FALSE, FALSE, 3);
	gtk_widget_set_tooltip_text(button, buttonspec->tooltiptext);
	gtk_widget_set_sensitive(button, !buttonspec->start_insensitive);

	return button;
}

static void add_buttons(struct gui_entry *ge, struct button_spec *buttonlist,
			int nbuttons)
{
	int i;

	for (i = 0; i < nbuttons; i++)
		ge->button[i] = add_button(ge->buttonbox, &buttonlist[i], ge);
}

static void on_info_bar_response(GtkWidget *widget, gint response,
                                 gpointer data)
{
	struct gui *ui = &main_ui;

	if (response == GTK_RESPONSE_OK) {
		gtk_widget_destroy(widget);
		ui->error_info_bar = NULL;
	}
}

void report_error(GError *error)
{
	struct gui *ui = &main_ui;

	if (ui->error_info_bar == NULL) {
		ui->error_info_bar = gtk_info_bar_new_with_buttons(GTK_STOCK_OK,
		                                               GTK_RESPONSE_OK,
		                                               NULL);
		g_signal_connect(ui->error_info_bar, "response", G_CALLBACK(on_info_bar_response), NULL);
		gtk_info_bar_set_message_type(GTK_INFO_BAR(ui->error_info_bar),
		                              GTK_MESSAGE_ERROR);
		
		ui->error_label = gtk_label_new(error->message);
		GtkWidget *container = gtk_info_bar_get_content_area(GTK_INFO_BAR(ui->error_info_bar));
		gtk_container_add(GTK_CONTAINER(container), ui->error_label);
		
		gtk_box_pack_start(GTK_BOX(ui->vbox), ui->error_info_bar, FALSE, FALSE, 0);
		gtk_widget_show_all(ui->vbox);
	} else {
		char buffer[256];
		snprintf(buffer, sizeof(buffer), "Failed to open file.");
		gtk_label_set(GTK_LABEL(ui->error_label), buffer);
	}
}

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
	ctext = gtk_combo_box_get_active_text(GTK_COMBO_BOX(cw->combo));
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

static int get_connection_details(char **host, int *port, int *type,
				  int *server_start)
{
	GtkWidget *dialog, *box, *vbox, *hbox, *frame, *pentry;
	struct connection_widgets cw;
	char *typeentry;

	dialog = gtk_dialog_new_with_buttons("Connection details",
			GTK_WINDOW(main_ui.window),
			GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL);

	frame = gtk_frame_new("Hostname / socket name");
	/* gtk_dialog_get_content_area() is 2.14 and newer */
	vbox = GTK_DIALOG(dialog)->vbox;
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

	cw.combo = gtk_combo_box_new_text();
	gtk_combo_box_append_text(GTK_COMBO_BOX(cw.combo), "IPv4");
	gtk_combo_box_append_text(GTK_COMBO_BOX(cw.combo), "IPv6");
	gtk_combo_box_append_text(GTK_COMBO_BOX(cw.combo), "local socket");
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
	g_signal_connect(GTK_OBJECT(cw.hentry), "changed", G_CALLBACK(hostname_cb), &cw);
	g_signal_connect(GTK_OBJECT(cw.combo), "changed", G_CALLBACK(hostname_cb), &cw);

	gtk_widget_show_all(dialog);

	if (gtk_dialog_run(GTK_DIALOG(dialog)) != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(dialog);
		return 1;
	}

	*host = strdup(gtk_entry_get_text(GTK_ENTRY(cw.hentry)));
	*port = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(pentry));

	typeentry = gtk_combo_box_get_active_text(GTK_COMBO_BOX(cw.combo));
	if (!typeentry || !strncmp(typeentry, "IPv4", 4))
		*type = Fio_client_ipv4;
	else if (!strncmp(typeentry, "IPv6", 4))
		*type = Fio_client_ipv6;
	else
		*type = Fio_client_socket;
	g_free(typeentry);

	*server_start = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cw.button));

	gtk_widget_destroy(dialog);
	return 0;
}

static void gfio_client_added(struct gui_entry *ge, struct fio_client *client)
{
	struct gfio_client *gc;

	gc = malloc(sizeof(*gc));
	memset(gc, 0, sizeof(*gc));
	gc->ge = ge;
	gc->client = fio_get_client(client);

	ge->client = gc;

	client->client_data = gc;
}

static GtkWidget *new_client_page(struct gui_entry *ge);

static struct gui_entry *alloc_new_gui_entry(struct gui *ui)
{
	struct gui_entry *ge;

	ge = malloc(sizeof(*ge));
	memset(ge, 0, sizeof(*ge));
	ge->state = GE_STATE_NEW;
	INIT_FLIST_HEAD(&ge->list);
	flist_add_tail(&ge->list, &ui->list);
	ge->ui = ui;
	return ge;
}

static struct gui_entry *get_new_ge_with_tab(const char *name)
{
	struct gui_entry *ge;

	ge = alloc_new_gui_entry(&main_ui);

	ge->vbox = new_client_page(ge);
	g_signal_connect(ge->vbox, "destroy", G_CALLBACK(ge_widget_destroy), ge);

	ge->page_label = gtk_label_new(name);
	ge->page_num = gtk_notebook_append_page(GTK_NOTEBOOK(main_ui.notebook), ge->vbox, ge->page_label);

	gtk_widget_show_all(main_ui.window);
	return ge;
}

static void file_new(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_new_ge_with_tab("Untitled");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(ui->notebook), ge->page_num);
}

/*
 * Return the 'ge' corresponding to the tab. If the active tab is the
 * main tab, open a new tab.
 */
static struct gui_entry *get_ge_from_page(gint cur_page, int *created)
{
	struct flist_head *entry;
	struct gui_entry *ge;

	if (!cur_page) {
		if (created)
			*created = 1;
		return get_new_ge_with_tab("Untitled");
	}

	if (created)
		*created = 0;

	flist_for_each(entry, &main_ui.list) {
		ge = flist_entry(entry, struct gui_entry, list);
		if (ge->page_num == cur_page)
			return ge;
	}

	return NULL;
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
		return get_ge_from_page(cur_page, NULL);

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

	if (!flist_empty(&ui->list)) {
		show_info_dialog(ui, "Error", "The main page view cannot be closed\n");
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

static int do_file_open(struct gui_entry *ge, const gchar *uri, char *host,
			int type, int port)
{
	struct fio_client *client;
	gchar *filename;

	filename = get_filename_from_uri(uri);

	ge->job_files = realloc(ge->job_files, (ge->nr_job_files + 1) * sizeof(char *));
	ge->job_files[ge->nr_job_files] = strdup(filename);
	ge->nr_job_files++;

	client = fio_client_add_explicit(&gfio_client_ops, host, type, port);
	if (!client) {
		GError *error;

		error = g_error_new(g_quark_from_string("fio"), 1,
				"Failed to add client %s", host);
		report_error(error);
		g_error_free(error);
		return 1;
	}

	gfio_client_added(ge, client);
	file_add_recent(ge->ui, uri);
	return 0;
}

static int do_file_open_with_tab(struct gui *ui, const gchar *uri)
{
	int port, type, server_start;
	struct gui_entry *ge;
	gint cur_page;
	char *host;
	int ret, ge_is_new = 0;

	/*
	 * Creates new tab if current tab is the main window, or the
	 * current tab already has a client.
	 */
	cur_page = gtk_notebook_get_current_page(GTK_NOTEBOOK(ui->notebook));
	ge = get_ge_from_page(cur_page, &ge_is_new);
	if (ge->client) {
		ge = get_new_ge_with_tab("Untitled");
		ge_is_new = 1;
	}

	gtk_notebook_set_current_page(GTK_NOTEBOOK(ui->notebook), ge->page_num);

	if (get_connection_details(&host, &port, &type, &server_start)) {
		if (ge_is_new)
			gtk_widget_destroy(ge->vbox);
			
		return 1;
	}

	ret = do_file_open(ge, uri, host, type, port);

	free(host);

	if (!ret) {
		if (server_start)
			gfio_start_server();
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
	GSList *filenames, *fn_glist;
	GtkFileFilter *filter;

	dialog = gtk_file_chooser_dialog_new("Open File",
		GTK_WINDOW(ui->window),
		GTK_FILE_CHOOSER_ACTION_OPEN,
		GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
		GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
		NULL);
	gtk_file_chooser_set_select_multiple(GTK_FILE_CHOOSER(dialog), TRUE);

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

	fn_glist = gtk_file_chooser_get_filenames(GTK_FILE_CHOOSER(dialog));

	gtk_widget_destroy(dialog);

	filenames = fn_glist;
	while (filenames != NULL) {
		if (do_file_open_with_tab(ui, filenames->data))
			break;
		filenames = g_slist_next(filenames);
	}

	g_slist_free(fn_glist);
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

	gtk_widget_ref(ui->log_tree);
	gtk_container_remove(GTK_CONTAINER(w), ui->log_tree);
	gtk_widget_destroy(w);
	ui->log_view = NULL;
}

static void view_log(GtkWidget *w, gpointer data)
{
	GtkWidget *win, *scroll, *vbox, *box;
	struct gui *ui = (struct gui *) data;

	if (ui->log_view)
		return;

	ui->log_view = win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "Log");
	gtk_window_set_default_size(GTK_WINDOW(win), 700, 500);

	scroll = gtk_scrolled_window_new(NULL, NULL);

	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	box = gtk_hbox_new(TRUE, 0);
	gtk_box_pack_start_defaults(GTK_BOX(box), ui->log_tree);
	g_signal_connect(box, "destroy", G_CALLBACK(view_log_destroy), ui);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), box);

	vbox = gtk_vbox_new(TRUE, 5);
	gtk_box_pack_start_defaults(GTK_BOX(vbox), scroll);

	gtk_container_add(GTK_CONTAINER(win), vbox);
	gtk_widget_show_all(win);
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
}

static void start_job_entry(GtkWidget *w, gpointer data)
{
	struct gui *ui = (struct gui *) data;
	struct gui_entry *ge;

	ge = get_ge_from_cur_tab(ui);
	if (ge)
		start_job_clicked(w, ge);
}

static void __update_graph_limits(struct gfio_graphs *g)
{
	line_graph_set_data_count_limit(g->iops_graph, gfio_graph_limit);
	line_graph_set_data_count_limit(g->bandwidth_graph, gfio_graph_limit);
}

static void update_graph_limits(void)
{
	struct flist_head *entry;
	struct gui_entry *ge;

	__update_graph_limits(&main_ui.graphs);

	flist_for_each(entry, &main_ui.list) {
		ge = flist_entry(entry, struct gui_entry, list);
		__update_graph_limits(&ge->graphs);
	}
}

static void preferences(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog, *frame, *box, **buttons, *vbox, *font;
	GtkWidget *hbox, *spin, *entry, *spin_int;
	int i;

	dialog = gtk_dialog_new_with_buttons("Preferences",
		GTK_WINDOW(main_ui.window),
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
		GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
		NULL);

	frame = gtk_frame_new("Graphing");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), frame, FALSE, FALSE, 5);
	vbox = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	hbox = gtk_hbox_new(FALSE, 5);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
	entry = gtk_label_new("Font face to use for graph labels");
	gtk_box_pack_start(GTK_BOX(hbox), entry, TRUE, TRUE, 5);

	font = gtk_font_button_new();
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
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), frame, FALSE, FALSE, 5);
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
	{ "ConnectJob", NULL, "Connect", "<Control>E", NULL, G_CALLBACK(connect_job_entry) },
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
				<menuitem name=\"Close\" action=\"CloseFile\" /> \
				<separator name=\"Separator1\"/> \
				<menuitem name=\"Open\" action=\"OpenFile\" /> \
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
				<menuitem name=\"Log\" action=\"ViewLog\" /> \
			</menu>\
			<menu name=\"Help\" action=\"HelpMenuAction\"> \
				<menuitem name=\"About\" action=\"About\" /> \
			</menu> \
		</menubar> \
	</ui> \
";

static void set_job_menu_visible(struct gui *ui, int visible)
{
	GtkWidget *job;

	job = gtk_ui_manager_get_widget(ui->uimanager, "/MainMenu/JobMenu");
	gtk_widget_set_sensitive(job, visible);
}

static GtkWidget *get_menubar_menu(GtkWidget *window, GtkUIManager *ui_manager,
				   struct gui *ui)
{
	GtkActionGroup *action_group = gtk_action_group_new("Menu");
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
	multitext_set_entry(&ge->eta.ioengine, index);
	multitext_set_entry(&ge->eta.iodepth, index);
}

static void combo_entry_destroy(GtkWidget *widget, gpointer data)
{
	struct gui_entry *ge = (struct gui_entry *) data;

	multitext_free(&ge->eta.iotype);
	multitext_free(&ge->eta.ioengine);
	multitext_free(&ge->eta.iodepth);
}

static GtkWidget *new_client_page(struct gui_entry *ge)
{
	GtkWidget *main_vbox, *probe, *probe_frame, *probe_box;
	GtkWidget *scrolled_window, *bottom_align, *top_align, *top_vbox;
	GdkColor white;

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
	ge->eta.ioengine.entry = new_info_entry_in_frame(probe_box, "IO Engine");
	ge->eta.iodepth.entry = new_info_entry_in_frame(probe_box, "IO Depth");
	ge->eta.jobs = new_info_entry_in_frame(probe_box, "Jobs");
	ge->eta.files = new_info_entry_in_frame(probe_box, "Open files");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, FALSE, FALSE, 3);
	ge->eta.read_bw = new_info_entry_in_frame(probe_box, "Read BW");
	ge->eta.read_iops = new_info_entry_in_frame(probe_box, "IOPS");
	ge->eta.write_bw = new_info_entry_in_frame(probe_box, "Write BW");
	ge->eta.write_iops = new_info_entry_in_frame(probe_box, "IOPS");

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
	gdk_color_parse("white", &white);
	ge->graphs.drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(ge->graphs.drawing_area),
		DRAWING_AREA_XDIM, DRAWING_AREA_YDIM);
	gtk_widget_modify_bg(ge->graphs.drawing_area, GTK_STATE_NORMAL, &white);
	g_signal_connect(G_OBJECT(ge->graphs.drawing_area), "expose_event",
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

	add_buttons(ge, buttonspeclist, ARRAYSIZE(buttonspeclist));

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
	GdkColor white;

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
	ui->eta.read_bw = new_info_entry_in_frame(probe_box, "Read BW");
	ui->eta.read_iops = new_info_entry_in_frame(probe_box, "IOPS");
	ui->eta.write_bw = new_info_entry_in_frame(probe_box, "Write BW");
	ui->eta.write_iops = new_info_entry_in_frame(probe_box, "IOPS");

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
	gdk_color_parse("white", &white);
	ui->graphs.drawing_area = gtk_drawing_area_new();
	gtk_widget_set_size_request(GTK_WIDGET(ui->graphs.drawing_area),
		DRAWING_AREA_XDIM, DRAWING_AREA_YDIM);
	gtk_widget_modify_bg(ui->graphs.drawing_area, GTK_STATE_NORMAL, &white);
	g_signal_connect(G_OBJECT(ui->graphs.drawing_area), "expose_event",
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
		return TRUE;
	}

	set_job_menu_visible(ui, 1);
	ge = get_ge_from_page(page, NULL);
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
				   gint x, gint y, GtkSelectionData *data,
				   guint info, guint time)
{
	struct gui *ui = &main_ui;
	gchar **uris;
	GtkWidget *source;
	int i;

	source = gtk_drag_get_source_widget(ctx);
	if (source && widget == gtk_widget_get_toplevel(source)) {
		gtk_drag_finish(ctx, FALSE, FALSE, time);
		return;
	}

	uris = gtk_selection_data_get_uris(data);
	if (!uris) {
		gtk_drag_finish(ctx, FALSE, FALSE, time);
		return;
	}

	i = 0;
	while (uris[i]) {
		if (do_file_open_with_tab(ui, uris[i]))
			break;
		i++;
	}

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
	if (!g_thread_supported())
		g_thread_init(NULL);
	gdk_threads_init();

	gtk_init(argc, argv);
	settings = gtk_settings_get_default();
	gtk_settings_set_long_property(settings, "gtk_tooltip_timeout", 10, "gfio setting");
	g_type_init();
	
	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 1024, 768);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK(quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK(quit_clicked), NULL);

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
	gtk_drag_dest_set(GTK_WIDGET(ui->window), GTK_DEST_DEFAULT_ALL, NULL, 0, GDK_ACTION_COPY);
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

	memset(&main_ui, 0, sizeof(main_ui));
	INIT_FLIST_HEAD(&main_ui.list);

	init_ui(&argc, &argv, &main_ui);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	return 0;
}
