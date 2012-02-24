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
#include <gtk/gtk.h>

struct gui {
	GtkWidget *window;
};

static void quit_clicked(__attribute__((unused)) GtkWidget *widget,
                __attribute__((unused)) gpointer data)
{
        gtk_main_quit();
}

static void init_ui(int *argc, char **argv[], struct gui *ui)
{
	gtk_init(argc, argv);
	
	ui->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(ui->window), "fio");
	gtk_window_set_default_size(GTK_WINDOW(ui->window), 700, 500);

	g_signal_connect(ui->window, "delete-event", G_CALLBACK (quit_clicked), NULL);
	g_signal_connect(ui->window, "destroy", G_CALLBACK (quit_clicked), NULL);

	gtk_widget_show_all(ui->window);
}

int main(int argc, char *argv[])
{
	struct gui ui;

	init_ui(&argc, &argv, &ui);
	gtk_main();
	return 0;
}
