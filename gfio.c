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
	GtkWidget *hostname_hbox;
	GtkWidget *hostname_label;
	GtkWidget *hostname_entry;
	GtkWidget *port_label;
	GtkWidget *port_entry;
	GtkWidget *hostname_combo_box; /* ipv4, ipv6 or socket */
	GtkWidget *scrolled_window;
	GtkWidget *textview;
	GtkWidget *error_info_bar;
	GtkWidget *error_label;
	GtkTextBuffer *text;
	pthread_t t;

	void *cookie;
	int nr_job_files;
	char **job_files;
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
	.text_op		= gfio_text_op,
	.disk_util		= gfio_disk_util_op,
	.thread_status		= gfio_thread_status_op,
	.group_stats		= gfio_group_stats_op,
	.eta			= gfio_eta_op,
	.probe			= gfio_probe_op,
	.thread_status_display	= gfio_update_thread_status,
};

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
        gtk_main_quit();
}

static void *job_thread(void *arg)
{
	struct gui *ui = arg;

	fio_handle_clients(&gfio_client_ops);
	gtk_widget_set_sensitive(ui->button[START_JOB_BUTTON], 1);
	return NULL;
}

static int send_job_files(struct gui *ui)
{
	int i, ret;

	for (i = 0; i < ui->nr_job_files; i++) {
		ret = fio_clients_send_ini(ui->job_files[i]);
		free(ui->job_files[i]);
		ui->job_files[i] = NULL;
		if (ret)
			return ret;
	}

	return 0;
}

static void start_job_thread(pthread_t *t, struct gui *ui)
{
	fio_clients_connect();

	if (send_job_files(ui)) {
		printf("Yeah, I didn't really like those options too much.\n");
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

static void on_info_bar_response(GtkWidget *widget, gint response,
                                 gpointer data)
{
	if (response == GTK_RESPONSE_OK) {
		gtk_widget_destroy(widget);
		ui.error_info_bar = NULL;
	}
}

void report_error(GError* error)
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

static void file_open(GtkWidget *w, gpointer data)
{
	GtkWidget *dialog;
	GSList *filenames, *fn_glist;
	GtkFileFilter *filter;

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
	filenames = fn_glist;
	while (filenames != NULL) {
		const char *hostname;

		ui.job_files = realloc(ui.job_files, (ui.nr_job_files + 1) * sizeof(char *));
		ui.job_files[ui.nr_job_files] = strdup(filenames->data);
		ui.nr_job_files++;

		hostname = gtk_entry_get_text(GTK_ENTRY(ui.hostname_entry));
		fio_client_add(hostname, &ui.cookie);
#if 0
		if (error) {
			report_error(error);
			g_error_free(error);
			error = NULL;
		}
#endif
			
		g_free(filenames->data);
		filenames = g_slist_next(filenames);
	}
	g_slist_free(fn_glist);
	gtk_widget_destroy(dialog);
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
	{ "OpenFile",       GTK_STOCK_OPEN, NULL,   "<Control>O", NULL, G_CALLBACK(file_open) },
        { "SaveFile",       GTK_STOCK_SAVE, NULL,   "<Control>S", NULL, G_CALLBACK(file_save) },
        { "Quit",           GTK_STOCK_QUIT, NULL,   "<Control>Q", NULL, G_CALLBACK(quit_clicked) },
	{ "About",          GTK_STOCK_ABOUT, NULL,  NULL, NULL, G_CALLBACK(about_dialog) },
};
static gint nmenu_items = sizeof (menu_items) / sizeof(menu_items[0]);

static const gchar *ui_string = " \
	<ui> \
		<menubar name=\"MainMenu\"> \
			<menu name=\"FileMenu\" action=\"FileMenuAction\"> \
				<menuitem name=\"Open\" action=\"OpenFile\" /> \
				<menuitem name=\"Save\" action=\"SaveFile\" /> \
				<separator name=\"Separator\"/> \
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
	GList *hostname_type_list = NULL;
	char portnum[20];
	GtkSettings *settings;
	GtkUIManager *uimanager;
	GtkWidget *menu;

	memset(ui, 0, sizeof(*ui));

	/* Magical g*thread incantation, you just need this thread stuff.
	 * Without it, the update that happens in gfio_update_thread_status
	 * doesn't really happen in a timely fashion, you need expose events
	 */
	if (!g_thread_supported ())
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
	gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(ui->hostname_combo_box)->entry), "IPv4");
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "IPv4"); 
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "local socket"); 
	hostname_type_list = g_list_append(hostname_type_list, (gpointer) "IPv6"); 
	gtk_combo_set_popdown_strings(GTK_COMBO(ui->hostname_combo_box), hostname_type_list);
	g_list_free(hostname_type_list);

	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_label);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_entry);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->port_label);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->port_entry);
	gtk_container_add(GTK_CONTAINER (ui->hostname_hbox), ui->hostname_combo_box);
	gtk_container_add(GTK_CONTAINER (ui->topvbox), ui->hostname_hbox);

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
	if (fio_init_options())
		return 1;

	init_ui(&argc, &argv, &ui);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	return 0;
}
