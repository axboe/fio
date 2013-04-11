#include <gtk/gtk.h>
#include <cairo.h>

#include "gfio.h"
#include "cairo_text_helpers.h"
#include "printing.h"


static struct printing_parameters {
	gdouble width, height, xdpi, ydpi;
	GtkPrintSettings *settings;
	GtkPageSetup *page_setup;
} print_params = { 0 };

static void begin_print(GtkPrintOperation *operation,
			GtkPrintContext *context, gpointer data)
{
	print_params.page_setup = gtk_print_context_get_page_setup(context);

	print_params.width = gtk_print_context_get_width(context);
	print_params.height = gtk_print_context_get_height(context);
	print_params.xdpi = gtk_print_context_get_dpi_x(context);
	print_params.ydpi = gtk_print_context_get_dpi_y(context);

	/* assume 1 page for now. */
	gtk_print_operation_set_n_pages(operation, 1);
}

static void results_draw_page(GtkPrintOperation *operation,
			      GtkPrintContext *context, gint page_nr,
			      gpointer data)
{
	cairo_t *cr;
	char str[20];
	double x, y;

	cr = gtk_print_context_get_cairo_context(context);

	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_set_line_width(cr, 5.0);
	cairo_move_to(cr, 0.0, 0.0);
	cairo_line_to(cr, print_params.width, print_params.height);
	cairo_move_to(cr, 0.0, print_params.height);
	cairo_line_to(cr, print_params.width, 0.0);
	cairo_stroke(cr);

	x = print_params.width / 4.0;
	y = print_params.height / 5.0;
	sprintf(str, "(%g,%g)", x, y);
	draw_right_justified_text(cr, "Sans", x, y, 12.0, str);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_set_line_width(cr, 2.0);
	cairo_move_to(cr, x, y - 30.0);
	cairo_line_to(cr, x, y + 30.0);
	cairo_move_to(cr, x - 30, y);
	cairo_line_to(cr, x + 30, y);

	y *= 4.0;
	x *= 2.0;
	sprintf(str, "(%g,%g)", x, y);
	draw_right_justified_text(cr, "Sans", x, y, 12.0, str);
	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_set_line_width(cr, 2.0);
	cairo_move_to(cr, x, y - 30.0);
	cairo_line_to(cr, x, y + 30.0);
	cairo_move_to(cr, x - 30, y);
	cairo_line_to(cr, x + 30, y);
	cairo_stroke(cr);
}

static void printing_error_dialog(GtkWidget *window, GError *print_error)
{
	GtkWidget *error_dialog;

	printf("printing_error_dialog called\n");
	printf("error message = %s\n", print_error->message);
	error_dialog = gtk_message_dialog_new(GTK_WINDOW(window),
			GTK_DIALOG_DESTROY_WITH_PARENT, GTK_MESSAGE_ERROR,
			GTK_BUTTONS_CLOSE, "Print error:\n%s",
			print_error->message);
	g_signal_connect(error_dialog, "response",
			G_CALLBACK(gtk_widget_destroy), NULL);
	gtk_widget_show(error_dialog);
}

static void results_print_done(GtkPrintOperation *operation,
			GtkPrintOperationResult result, gpointer data)
{
	GError *print_error;
	struct gui_entry *ge = data;

	if (result != GTK_PRINT_OPERATION_RESULT_ERROR)
		return;

	gtk_print_operation_get_error(operation, &print_error);
	printing_error_dialog(ge->results_window, print_error);
	g_error_free(print_error);
}

void gfio_print_results(struct gui_entry *ge)
{
	GtkPrintOperation *print;
	GtkPrintOperationResult res;
	GError *print_error;

	print = gtk_print_operation_new();
	if (print_params.settings != NULL)
		gtk_print_operation_set_print_settings(print, print_params.settings);

	if (print_params.page_setup != NULL)
		gtk_print_operation_set_default_page_setup(print, print_params.page_setup);

	g_signal_connect(print, "begin_print", G_CALLBACK(begin_print), NULL);
	g_signal_connect(print, "draw_page", G_CALLBACK(results_draw_page), NULL);
	g_signal_connect(print, "done", G_CALLBACK(results_print_done), NULL);
	gtk_print_operation_set_allow_async(print, TRUE);
	res = gtk_print_operation_run(print, GTK_PRINT_OPERATION_ACTION_PRINT_DIALOG,
		GTK_WINDOW(ge->results_window), &print_error);

	/*
	 * Something's not quite right about the error handling.  If I print
	 * to a file, and the file exists, and I don't have write permission
	 * on that file but attempt to replace it anyway, then it just kind of
	 * hangs and I don't get into any of this error handling stuff at all,
	 * neither here, nor in results_print_done().
	 */

	if (res == GTK_PRINT_OPERATION_RESULT_ERROR) {
		printing_error_dialog(ge->results_window, print_error);
		g_error_free(print_error);
	} else {
		if (res == GTK_PRINT_OPERATION_RESULT_APPLY) {
			if (print_params.settings != NULL)
				g_object_unref(print_params.settings);
			print_params.settings = g_object_ref(gtk_print_operation_get_print_settings(print));
		}
	}
	g_object_unref(print);
}
