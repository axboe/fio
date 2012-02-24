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

#include "fio_initialization.h"
#include "fio.h"

#define ARRAYSIZE(x) (sizeof((x)) / (sizeof((x)[0])))

typedef void (*clickfunction)(GtkWidget *widget, gpointer data);

static void quit_clicked(GtkWidget *widget, gpointer data);
static void start_job_clicked(GtkWidget *widget, gpointer data);

static struct button_spec {
	const char *buttontext;
	clickfunction f;
	const char *tooltiptext;
} buttonspeclist[] = {
#define START_JOB_BUTTON 0
	{ "Start Job",
		start_job_clicked,
		"Send current fio job to fio server to be executed" },
#define QUIT_BUTTON 1
	{ "Quit", quit_clicked, "Quit gfio" },
};

struct gui {
	int argc;
	char **argv;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *topvbox;
	GtkWidget *topalign;
	GtkWidget *bottomalign;
	GtkWidget *thread_status_pb;
	GtkWidget *buttonbox;
	GtkWidget *button[ARRAYSIZE(buttonspeclist)];
	GtkWidget *hostname_hbox;
	GtkWidget *hostname_label;
	GtkWidget *hostname_entry;
	GtkWidget *port_label;
	GtkWidget *port_entry;
	GtkWidget *hostname_combo_box; /* ipv4, ipv6 or socket */
	GtkWidget *jobfile_hbox;
	GtkWidget *jobfile_label;
	GtkWidget *jobfile_entry;
	GtkWidget *scrolled_window;
	GtkWidget *textview;
	GtkTextBuffer *text;
	pthread_t t;
} ui;

static void gfio_text_op(struct fio_client *client,
                FILE *f, __u16 pdu_len, const char *buf)
{
	GtkTextBuffer *buffer;
	GtkTextIter end;

	buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(ui.textview));
	gdk_threads_enter();
	gtk_text_buffer_get_end_iter(buffer, &end);
	gtk_text_buffer_insert(buffer, &end, buf, -1);
	gdk_threads_leave();
	gtk_text_view_scroll_to_iter(GTK_TEXT_VIEW(ui.textview),
					&end, 0.0, FALSE, 0.0,0.0);
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

static void gfio_eta_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	fio_client_ops.eta(client, cmd);
}

static void gfio_probe_op(struct fio_client *client, struct fio_net_cmd *cmd)
{
	printf("gfio_probe_op called\n");
	fio_client_ops.probe(client, cmd);
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

struct client_ops gfio_client_ops = {
	gfio_text_op,
	gfio_disk_util_op,
	gfio_thread_status_op,
	gfio_group_stats_op,
	gfio_eta_op,
	gfio_probe_op,
	gfio_update_thread_status,
};

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
        gtk_main_quit();
}

static void add_arg(char **argv, int index, const char *value)
{
	argv[index] = malloc(strlen(value) + 1);
	strcpy(argv[index], value);
}

static void free_args(int argc, char **argv)
{
	int i;

	for (i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

static void *job_thread(void *arg)
{
	struct gui *ui = arg;

	fio_handle_clients(&gfio_client_ops);
	gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
	free_args(ui->argc, ui->argv);
	return NULL;
}

static void construct_options(struct gui *ui, int *argc, char ***argv)
{
	const char *hostname, *hostname_type, *port, *jobfile;
	char newarg[200];
	
	hostname_type = gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(ui->hostname_combo_box)->entry));
	hostname = gtk_entry_get_text(GTK_ENTRY(ui->hostname_entry));
	port = gtk_entry_get_text(GTK_ENTRY(ui->port_entry));
	jobfile = gtk_entry_get_text(GTK_ENTRY(ui->jobfile_entry));

	*argc = 3;
	*argv = malloc(*argc * sizeof(**argv)); 	
	add_arg(*argv, 0,  "gfio");
	snprintf(newarg, sizeof(newarg) - 1, "--client=%s", hostname);
	add_arg(*argv, 1, newarg);
	add_arg(*argv, 2, jobfile);
}

static void start_job_thread(pthread_t *t, struct gui *ui)
{
	construct_options(ui, &ui->argc, &ui->argv);
	if (parse_options(ui->argc, ui->argv)) {
		printf("Yeah, I didn't really like those options too much.\n");
		free_args(ui->argc, ui->argv);
		gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
		return;
	}
	pthread_create(t, NULL, job_thread, ui);
}

static void start_job_clicked(__attribute__((unused)) GtkWidget *widget,
                gpointer data)
{
	struct gui *ui = data;

	printf("Start job button was clicked.\n");
	gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 0);
	start_job_thread(&ui->t, ui);
}

static void add_button(struct gui *ui, int i, GtkWidget *buttonbox,
			struct button_spec *buttonspec)
{
	ui->button[i] = gtk_button_new_with_label(buttonspec->buttontext);
	g_signal_connect(ui->button[i], "clicked", G_CALLBACK (buttonspec->f), ui);
	gtk_box_pack_start(GTK_BOX (ui->buttonbox), ui->button[i], TRUE, TRUE, 0);
	gtk_widget_set_tooltip_text(ui->button[i], buttonspeclist[i].tooltiptext);
}

static void add_buttons(struct gui *ui,
				struct button_spec *buttonlist,
				int nbuttons)
{
	int i;

	for (i = 0; i < nbuttons; i++)
		add_button(ui, i, ui->buttonbox, &buttonlist[i]);
}

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	GList *hostname_type_list = NULL;
	char portnum[20];

	/* Magical g*thread incantation, you just need this thread stuff.
	 * Without it, the update that happens in gfio_update_thread_status
	 * doesn't really happen in a timely fashion, you need expose events
	 */
	if (!g_thread_supported ())
		g_thread_init(NULL);
	gdk_threads_init();

	gtk_init(argc, argv);
	
	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 700, 500);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK (quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK (quit_clicked), NULL);

	ui->vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (ui->window), ui->vbox);

	/*
	 * Set up alignments for widgets at the top of ui, 
	 * align top left, expand horizontally but not vertically
	 */
	ui->topalign = gtk_alignment_new(0, 0, 1, 0);
	ui->topvbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER(ui->topalign), ui->topvbox);
	gtk_box_pack_start(GTK_BOX(ui->vbox), ui->topalign, FALSE, FALSE, 0);

	/*
	 * Set up hostname label + entry, port label + entry,
	 */
	ui->hostname_hbox = gtk_hbox_new(FALSE, 0);
	ui->hostname_label = gtk_label_new("Host:");
	ui->hostname_entry = gtk_entry_new();
	gtk_entry_set_text(GTK_ENTRY(ui->hostname_entry), "localhost");
	ui->port_label = gtk_label_new("Port:");
	ui->port_entry = gtk_entry_new();
	snprintf(portnum, sizeof(portnum) - 1, "%d", FIO_NET_PORT);
	gtk_entry_set_text(GTK_ENTRY(ui->port_entry), (gchar *) portnum);

	/*
	 * Set up combo box for address type
	 */
	ui->hostname_combo_box = gtk_combo_new();
	gtk_entry_set_text(GTK_ENTRY (GTK_COMBO(ui->hostname_combo_box)->entry), "IPv4");
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "IPv4"); 
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "local socket"); 
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "IPv6"); 
	gtk_combo_set_popdown_strings (GTK_COMBO (ui->hostname_combo_box), hostname_type_list);
	g_list_free(hostname_type_list);

	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_label);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_entry);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->port_label);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->port_entry);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_combo_box);
	gtk_container_add(GTK_CONTAINER (ui->topvbox), ui->hostname_hbox);

	/*
	 * Set up jobfile text entry (temporary until gui really works)
	 */
	ui->jobfile_hbox = gtk_hbox_new(FALSE, 0);
	ui->jobfile_label = gtk_label_new("Job file:");
	ui->jobfile_entry = gtk_entry_new();
	gtk_container_add(GTK_CONTAINER (ui->jobfile_hbox), ui->jobfile_label);
	gtk_container_add(GTK_CONTAINER (ui->jobfile_hbox), ui->jobfile_entry);
	gtk_container_add(GTK_CONTAINER (ui->topvbox), ui->jobfile_hbox);

	/*
	 * Set up thread status progress bar
	 */
	ui->thread_status_pb = gtk_progress_bar_new();
	gtk_progress_bar_set_fraction(
		GTK_PROGRESS_BAR(ui->thread_status_pb), 0.0);
	gtk_progress_bar_set_text(
		GTK_PROGRESS_BAR(ui->thread_status_pb), "No jobs running");
	gtk_container_add(GTK_CONTAINER (ui->topvbox), ui->thread_status_pb);

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
	gtk_widget_show_all(ui->window);
}

int main(int argc, char *argv[], char *envp[])
{
	if (initialize_fio(envp))
		return 1;

	init_ui(&argc, &argv, &ui);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	return 0;
}
