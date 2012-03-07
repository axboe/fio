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

#include <glib.h>
#include <cairo.h>
#include <gtk/gtk.h>

#include "fio.h"
#include "graph.h"

static int gfio_server_running;
static const char *gfio_graph_font;

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
#define DRAWING_AREA_XDIM 1000
#define DRAWING_AREA_YDIM 400
	GtkWidget *drawing_area;
	int drawing_area_xdim;
	int drawing_area_ydim;
	GtkWidget *error_info_bar;
	GtkWidget *error_label;
	GtkWidget *results_notebook;
	GtkWidget *results_window;
	GtkListStore *log_model;
	GtkWidget *log_tree;
	GtkWidget *log_view;
	GtkTextBuffer *text;
	struct probe_widget probe;
	struct eta_widget eta;
	int connected;
	pthread_t t;
	pthread_t server_t;

	struct graph *iops_graph;
	struct graph *bandwidth_graph;
	struct fio_client *client;
	int nr_job_files;
	char **job_files;
} ui;

struct gfio_client {
	struct gui *ui;
	GtkWidget *results_widget;
	GtkWidget *disk_util_frame;
};

static void setup_iops_graph(struct gui *ui)
{
	if (ui->iops_graph)
		graph_free(ui->iops_graph);
	ui->iops_graph = graph_new(DRAWING_AREA_XDIM / 2.0,
					DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(ui->iops_graph, "IOPS");
	graph_x_title(ui->iops_graph, "Time (secs)");
	graph_add_label(ui->iops_graph, "Read IOPS");
	graph_add_label(ui->iops_graph, "Write IOPS");
	graph_set_color(ui->iops_graph, "Read IOPS", 0.13, 0.54, 0.13);
	graph_set_color(ui->iops_graph, "Write IOPS", 1.0, 0.0, 0.0);
	line_graph_set_data_count_limit(ui->iops_graph, 100);
}

static void setup_bandwidth_graph(struct gui *ui)
{
	if (ui->bandwidth_graph)
		graph_free(ui->bandwidth_graph);
	ui->bandwidth_graph = graph_new(DRAWING_AREA_XDIM / 2.0,
					DRAWING_AREA_YDIM, gfio_graph_font);
	graph_title(ui->bandwidth_graph, "Bandwidth");
	graph_x_title(ui->bandwidth_graph, "Time (secs)");
	graph_add_label(ui->bandwidth_graph, "Read Bandwidth");
	graph_add_label(ui->bandwidth_graph, "Write Bandwidth");
	graph_set_color(ui->bandwidth_graph, "Read Bandwidth", 0.13, 0.54, 0.13);
	graph_set_color(ui->bandwidth_graph, "Write Bandwidth", 1.0, 0.0, 0.0);
	line_graph_set_data_count_limit(ui->bandwidth_graph, 100);
}

static void clear_ui_info(struct gui *ui)
{
	gtk_label_set_text(GTK_LABEL(ui->probe.hostname), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.os), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.arch), "");
	gtk_label_set_text(GTK_LABEL(ui->probe.fio_ver), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.name), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.iotype), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.ioengine), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.iodepth), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.jobs), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.files), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.read_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.read_iops), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.write_bw), "");
	gtk_entry_set_text(GTK_ENTRY(ui->eta.write_iops), "");
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

static void gfio_set_connected(struct gui *ui, int connected)
{
	if (connected) {
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
		ui->connected = 1;
		gtk_button_set_label(GTK_BUTTON(ui->button[CONNECT_BUTTON]), "Disconnect");
		gtk_widget_set_sensitive(ui->button[CONNECT_BUTTON], 1);
	} else {
		ui->connected = 0;
		gtk_button_set_label(GTK_BUTTON(ui->button[CONNECT_BUTTON]), "Connect");
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 0);
		gtk_widget_set_sensitive(ui->button[CONNECT_BUTTON], 1);
	}
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
	struct gui *ui = (struct gui *) data;

	gtk_widget_destroy(w);
	ui->results_window = NULL;
	ui->results_notebook = NULL;
	return TRUE;
}

static GtkWidget *get_results_window(struct gui *ui)
{
	GtkWidget *win, *notebook;

	if (ui->results_window)
		return ui->results_notebook;

	win = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(win), "Results");
	g_signal_connect(win, "delete-event", G_CALLBACK(results_window_delete), ui);
	g_signal_connect(win, "destroy", G_CALLBACK(results_window_delete), ui);

	notebook = gtk_notebook_new();
	gtk_container_add(GTK_CONTAINER(win), notebook);

	ui->results_window = win;
	ui->results_notebook = notebook;
	return ui->results_notebook;
}

static void gfio_display_ts(struct fio_client *client, struct thread_stat *ts,
			    struct group_run_stats *rs)
{
	GtkWidget *res_win, *box, *vbox, *entry;
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();

	res_win = get_results_window(gc->ui);

	vbox = gtk_vbox_new(FALSE, 3);

	box = gtk_hbox_new(TRUE, 3);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);

	gtk_notebook_append_page(GTK_NOTEBOOK(res_win), vbox, gtk_label_new(ts->name));

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
	entry = new_info_entry_in_frame(box, "Error");
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

	gtk_widget_show_all(gc->ui->results_window);
	gdk_threads_leave();
}

static void gfio_text_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_text_pdu *p = (struct cmd_text_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	GtkTreeIter iter;
	struct tm *tm;
	time_t sec;
	char tmp[64], timebuf[80];

	sec = p->log_sec;
	tm = localtime(&sec);
	strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", tm);
	sprintf(timebuf, "%s.%03ld", tmp, p->log_usec / 1000);

	gdk_threads_enter();

	gtk_list_store_append(gc->ui->log_model, &iter);
	gtk_list_store_set(gc->ui->log_model, &iter, 0, timebuf, -1);
	gtk_list_store_set(gc->ui->log_model, &iter, 1, client->hostname, -1);
	gtk_list_store_set(gc->ui->log_model, &iter, 2, p->level, -1);
	gtk_list_store_set(gc->ui->log_model, &iter, 3, p->buf, -1);

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
	gdk_threads_enter();
	printf("gfio_group_stats_op called\n");
	fio_client_ops.group_stats(client, cmd);
	gdk_threads_leave();
}

static gint on_config_drawing_area(GtkWidget *w, GdkEventConfigure *event)
{
	ui.drawing_area_xdim = w->allocation.width;
	ui.drawing_area_ydim = w->allocation.height;
	return TRUE;
}

static int on_expose_drawing_area(GtkWidget *w, GdkEvent *event, gpointer p)
{
	struct gui *ui = (struct gui *) p;
	cairo_t *cr;

	graph_set_size(ui->iops_graph, ui->drawing_area_xdim / 2.0,
					ui->drawing_area_ydim);
	graph_set_size(ui->bandwidth_graph, ui->drawing_area_xdim / 2.0,
					ui->drawing_area_ydim);
	cr = gdk_cairo_create(w->window);

	cairo_set_source_rgb(cr, 0, 0, 0);

	cairo_save(cr);
	cairo_translate(cr, 0, 0);
	line_graph_draw(ui->bandwidth_graph, cr);
	cairo_stroke(cr);
	cairo_restore(cr);

	cairo_save(cr);
	cairo_translate(cr, ui->drawing_area_xdim / 2.0, 0);
	line_graph_draw(ui->iops_graph, cr);
	cairo_stroke(cr);
	cairo_restore(cr);
	cairo_destroy(cr);

	return FALSE;
}

static void gfio_update_eta(struct jobs_eta *je)
{
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
	gtk_entry_set_text(GTK_ENTRY(ui.eta.jobs), tmp);
	sprintf(tmp, "%u", je->files_open);
	gtk_entry_set_text(GTK_ENTRY(ui.eta.files), tmp);

#if 0
	if (je->m_rate[0] || je->m_rate[1] || je->t_rate[0] || je->t_rate[1]) {
	if (je->m_rate || je->t_rate) {
		char *tr, *mr;

		mr = num2str(je->m_rate, 4, 0, i2p);
		tr = num2str(je->t_rate, 4, 0, i2p);
		gtk_entry_set_text(GTK_ENTRY(ui.eta);
		p += sprintf(p, ", CR=%s/%s KB/s", tr, mr);
		free(tr);
		free(mr);
	} else if (je->m_iops || je->t_iops)
		p += sprintf(p, ", CR=%d/%d IOPS", je->t_iops, je->m_iops);

	gtk_entry_set_text(GTK_ENTRY(ui.eta.cr_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ui.eta.cr_iops), "---");
	gtk_entry_set_text(GTK_ENTRY(ui.eta.cw_bw), "---");
	gtk_entry_set_text(GTK_ENTRY(ui.eta.cw_iops), "---");
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

		gtk_entry_set_text(GTK_ENTRY(ui.eta.read_bw), rate_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ui.eta.read_iops), iops_str[0]);
		gtk_entry_set_text(GTK_ENTRY(ui.eta.write_bw), rate_str[1]);
		gtk_entry_set_text(GTK_ENTRY(ui.eta.write_iops), iops_str[1]);

		graph_add_xy_data(ui.iops_graph, "Read IOPS", je->elapsed_sec, je->iops[0]);
		graph_add_xy_data(ui.iops_graph, "Write IOPS", je->elapsed_sec, je->iops[1]);
		graph_add_xy_data(ui.bandwidth_graph, "Read Bandwidth", je->elapsed_sec, je->rate[0]);
		graph_add_xy_data(ui.bandwidth_graph, "Write Bandwidth", je->elapsed_sec, je->rate[1]);

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
	gdk_threads_leave();
}

static void gfio_probe_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_probe_pdu *probe = (struct cmd_probe_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui *ui = gc->ui;
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

	gtk_label_set_text(GTK_LABEL(ui->probe.hostname), (char *) probe->hostname);
	gtk_label_set_text(GTK_LABEL(ui->probe.os), os);
	gtk_label_set_text(GTK_LABEL(ui->probe.arch), arch);
	sprintf(buf, "%u.%u.%u", probe->fio_major, probe->fio_minor, probe->fio_patch);
	gtk_label_set_text(GTK_LABEL(ui->probe.fio_ver), buf);

	gfio_set_connected(ui, 1);

	gdk_threads_leave();
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
	gtk_widget_queue_draw(ui.window);
}

static void gfio_quit_op(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;

	gdk_threads_enter();
	gfio_set_connected(gc->ui, 0);
	gdk_threads_leave();
}

static void gfio_add_job_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	struct cmd_add_job_pdu *p = (struct cmd_add_job_pdu *) cmd->payload;
	struct gfio_client *gc = client->client_data;
	struct gui *ui = gc->ui;
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

	gdk_threads_enter();

	gtk_entry_set_text(GTK_ENTRY(ui->eta.name), (gchar *) p->jobname);
	gtk_entry_set_text(GTK_ENTRY(ui->eta.iotype), ddir_str(p->rw));
	gtk_entry_set_text(GTK_ENTRY(ui->eta.ioengine), (gchar *) p->ioengine);

	sprintf(tmp, "%u", p->iodepth);
	gtk_entry_set_text(GTK_ENTRY(ui->eta.iodepth), tmp);

	gdk_threads_leave();
}

static void gfio_client_timed_out(struct fio_client *client)
{
	struct gfio_client *gc = client->client_data;
	GtkWidget *dialog, *label, *content;
	char buf[256];

	gdk_threads_enter();

	gfio_set_connected(gc->ui, 0);
	clear_ui_info(gc->ui);

	sprintf(buf, "Client %s: timeout talking to server.\n", client->hostname);

	dialog = gtk_dialog_new_with_buttons("Timed out!",
			GTK_WINDOW(gc->ui->window),
			GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_OK, NULL);

	/* gtk_dialog_get_content_area() is 2.14 and newer */
	content = GTK_DIALOG(dialog)->vbox;

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
	.eta			= gfio_update_eta,
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
		gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(ui->thread_status_pb), 0.0);
		if (!fio_clients_connect()) {
			pthread_create(&ui->t, NULL, job_thread, NULL);
			gtk_widget_set_sensitive(ui->button[CONNECT_BUTTON], 0);
		}
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
			GTK_WINDOW(ui.window),
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

static void gfio_client_added(struct gui *ui, struct fio_client *client)
{
	struct gfio_client *gc;

	gc = malloc(sizeof(*gc));
	memset(gc, 0, sizeof(*gc));
	gc->ui = ui;

	client->client_data = gc;
}

static void file_open(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog;
	struct gui *ui = data;
	GSList *filenames, *fn_glist;
	GtkFileFilter *filter;
	char *host;
	int port, type, server_start;

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
		struct fio_client *client;

		ui->job_files = realloc(ui->job_files, (ui->nr_job_files + 1) * sizeof(char *));
		ui->job_files[ui->nr_job_files] = strdup(filenames->data);
		ui->nr_job_files++;

		client = fio_client_add_explicit(&gfio_client_ops, host, type, port);
		if (!client) {
			GError *error;

			error = g_error_new(g_quark_from_string("fio"), 1,
					"Failed to add client %s", host);
			report_error(error);
			g_error_free(error);
		}
		gfio_client_added(ui, client);
			
		g_free(filenames->data);
		filenames = g_slist_next(filenames);
	}
	free(host);

	if (server_start)
		gfio_start_server(ui);
err:
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

static void preferences(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog, *frame, *box, **buttons, *vbox, *font;
	int i;

	dialog = gtk_dialog_new_with_buttons("Preferences",
		GTK_WINDOW(ui.window),
		GTK_DIALOG_DESTROY_WITH_PARENT,
		GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
		GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT,
		NULL);

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

	frame = gtk_frame_new("Graph font");
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), frame, FALSE, FALSE, 5);
	vbox = gtk_vbox_new(FALSE, 6);
	gtk_container_add(GTK_CONTAINER(frame), vbox);

	font = gtk_font_button_new();
	gtk_box_pack_start(GTK_BOX(vbox), font, FALSE, FALSE, 5);

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

	g_free (license_trans);
}

static GtkActionEntry menu_items[] = {
	{ "FileMenuAction", GTK_STOCK_FILE, "File", NULL, NULL, NULL},
	{ "ViewMenuAction", GTK_STOCK_FILE, "View", NULL, NULL, NULL},
	{ "HelpMenuAction", GTK_STOCK_HELP, "Help", NULL, NULL, NULL},
	{ "OpenFile", GTK_STOCK_OPEN, NULL,   "<Control>O", NULL, G_CALLBACK(file_open) },
	{ "SaveFile", GTK_STOCK_SAVE, NULL,   "<Control>S", NULL, G_CALLBACK(file_save) },
	{ "Preferences", GTK_STOCK_PREFERENCES, NULL, "<Control>p", NULL, G_CALLBACK(preferences) },
	{ "ViewLog", NULL, "Log", "<Control>l", NULL, G_CALLBACK(view_log) },
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
			<menu name=\"ViewMenu\" action=\"ViewMenuAction\"> \
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

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	GtkSettings *settings;
	GtkUIManager *uimanager;
	GtkWidget *menu, *probe, *probe_frame, *probe_box;
	GdkColor white;

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
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 700, 700);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK(quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK(quit_clicked), NULL);

	ui->vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (ui->window), ui->vbox);

	uimanager = gtk_ui_manager_new();
	menu = get_menubar_menu(ui->window, uimanager, ui);
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

	ui->eta.name = new_info_entry_in_frame(probe_box, "Name");
	ui->eta.iotype = new_info_entry_in_frame(probe_box, "IO");
	ui->eta.ioengine = new_info_entry_in_frame(probe_box, "IO Engine");
	ui->eta.iodepth = new_info_entry_in_frame(probe_box, "IO Depth");
	ui->eta.jobs = new_info_entry_in_frame(probe_box, "Jobs");
	ui->eta.files = new_info_entry_in_frame(probe_box, "Open files");

	probe_box = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(probe_frame), probe_box, TRUE, FALSE, 3);
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
	ui->drawing_area = gtk_drawing_area_new();
	ui->drawing_area_xdim = DRAWING_AREA_XDIM;
	ui->drawing_area_ydim = DRAWING_AREA_YDIM;
	gtk_widget_set_size_request(GTK_WIDGET(ui->drawing_area), 
			ui->drawing_area_xdim, ui->drawing_area_ydim);
	gtk_widget_modify_bg(ui->drawing_area, GTK_STATE_NORMAL, &white);
	g_signal_connect(G_OBJECT(ui->drawing_area), "expose_event",
				G_CALLBACK (on_expose_drawing_area), ui);
	g_signal_connect(G_OBJECT(ui->drawing_area), "configure_event",
				G_CALLBACK (on_config_drawing_area), ui);
	ui->scrolled_window = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(ui->scrolled_window),
					GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(ui->scrolled_window),
					ui->drawing_area);
	gtk_box_pack_start(GTK_BOX(ui->vbox), ui->scrolled_window,
			TRUE, TRUE, 0);

	setup_iops_graph(ui);
	setup_bandwidth_graph(ui);

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

	gfio_ui_setup_log(ui);

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
