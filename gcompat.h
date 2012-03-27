#ifndef GFIO_GTK_COMPAT
#define GFIO_GTK_COMPAT

#include <gtk/gtk.h>

#if GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 24
struct GtkComboBoxText;
typedef GtkComboBox GtkComboBoxText;
GtkWidget *gtk_combo_box_text_new(void);
GtkWidget *gtk_combo_box_text_new_with_entry(void);
void gtk_combo_box_text_append_text(GtkComboBoxText *combo_box, const gchar *text);
void gtk_combo_box_text_insert_text(GtkComboBoxText *combo_box, gint position, const gchar *text);
void gtk_combo_box_text_prepend_text(GtkComboBoxText *combo_box, const gchar *text);
void gtk_combo_box_text_remove(GtkComboBoxText *combo_box, gint position);
gchar *gtk_combo_box_text_get_active_text(GtkComboBoxText *combo_box);

#define GTK_COMBO_BOX_TEXT	GTK_COMBO_BOX
#endif /* GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 24 */

#if GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 14
static inline GtkWidget *gtk_dialog_get_content_area(GtkDialog *dialog)
{
	return dialog->vbox;
}
static inline GdkWindow *gtk_widget_get_window(GtkWidget *w)
{
	return w->window;
}
#endif

#if GTK_MAJOR_VERSION < 3
guint gtk_widget_get_allocated_width(GtkWidget *w);
guint gtk_widget_get_allocated_height(GtkWidget *w);
#endif

#if GTK_MAJOR_VERSION == 3
#define GFIO_DRAW_EVENT		"draw"
#elif GTK_MAJOR_VERSION == 2
#define GFIO_DRAW_EVENT		"expose_event"
#endif

#if GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 18
void gtk_widget_set_can_focus(GtkWidget *widget, gboolean can_focus);
#endif

#endif
