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

#include <gtk/gtk.h>

#include "fio_initialization.h"
#include "fio.h"

static struct client_ops *gfio_client_ops = &fio_client_ops;

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
	GtkWidget *window;
	GtkWidget *buttonbox;
	GtkWidget *button[ARRAYSIZE(buttonspeclist)];
};

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
        gtk_main_quit();
}

static void start_job_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
	printf("Start job button was clicked.\n");
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

	ui->buttonbox = gtk_hbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (ui->window), ui->buttonbox);
	for (i = 0; i < nbuttons; i++)
		add_button(ui, i, ui->buttonbox, &buttonlist[i]);
}

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	gtk_init(argc, argv);
	
	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 700, 500);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK (quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK (quit_clicked), NULL);

	add_buttons(ui, buttonspeclist, ARRAYSIZE(buttonspeclist));
	gtk_widget_show_all(ui->window);
}

int main(int argc, char *argv[], char *envp[])
{
	struct gui ui;

	if (initialize_fio(envp))
		return 1;
	init_ui(&argc, &argv, &ui);
	gtk_main();
	return 0;
}
