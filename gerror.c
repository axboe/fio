#include <locale.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <gtk/gtk.h>

#include "gfio.h"
#include "gerror.h"

static void on_info_bar_response(GtkWidget *widget, gint response,
				 gpointer data)
{
	struct gui *ui = (struct gui *) data;

	if (response == GTK_RESPONSE_OK) {
		gtk_widget_destroy(widget);
		ui->error_info_bar = NULL;
	}
}

static void report_error(struct gui_entry *ge, GError *error)
{
	struct gui *ui = ge->ui;

	if (ui->error_info_bar == NULL) {
		GtkWidget *container;

		ui->error_info_bar = gtk_info_bar_new_with_buttons(GTK_STOCK_OK,
						GTK_RESPONSE_OK, NULL);
		g_signal_connect(ui->error_info_bar, "response", G_CALLBACK(on_info_bar_response), ui);
		gtk_info_bar_set_message_type(GTK_INFO_BAR(ui->error_info_bar),
						GTK_MESSAGE_ERROR);

		ui->error_label = gtk_label_new(error->message);
		container = gtk_info_bar_get_content_area(GTK_INFO_BAR(ui->error_info_bar));
		gtk_container_add(GTK_CONTAINER(container), ui->error_label);

		gtk_box_pack_start(GTK_BOX(ui->vbox), ui->error_info_bar, FALSE, FALSE, 0);
		gtk_widget_show_all(ui->vbox);
	} else {
		char buffer[256];
		snprintf(buffer, sizeof(buffer), "Failed to open file.");
		gtk_label_set_text(GTK_LABEL(ui->error_label), buffer);
	}
}

void gfio_report_error(struct gui_entry *ge, const char *format, ...)
{
	va_list args;
	GError *error;

	va_start(args, format);
	error = g_error_new_valist(g_quark_from_string("fio"), 1, format, args);
	va_end(args);

	report_error(ge, error);
	g_error_free(error);
}

void gfio_report_info(struct gui *ui, const char *title, const char *message)
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
