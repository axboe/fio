#include <gtk/gtk.h>

#include "gcompat.h"

#if GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 24

GtkWidget *gtk_combo_box_text_new(void)
{
	return gtk_combo_box_new();
}

void gtk_combo_box_text_append_text(GtkComboBoxText *combo_box,
				    const gchar *text)
{
	gtk_combo_box_append_text(GTK_COMBO_BOX(combo_box), text);
}

void gtk_combo_box_text_insert_text(GtkComboBoxText *combo_box, gint position,
				    const gchar *text)
{
	gtk_combo_box_insert_text(GTK_COMBO_BOX(combo_box), position, text);
}

void gtk_combo_box_text_prepend_text(GtkComboBoxText *combo_box,
				     const gchar *text)
{
	gtk_combo_box_prepend_text(GTK_COMBO_BOX(combo_box), text);
}

gchar *gtk_combo_box_text_get_active_text(GtkComboBoxText *combo_box)
{
	return gtk_combo_box_get_active_text(GTK_COMBO_BOX(combo_box));
}

#endif

#if GTK_MAJOR_VERSION < 3

guint gtk_widget_get_allocated_width(GtkWidget *w)
{
	return w->allocation.width;
}

guint gtk_widget_get_allocated_height(GtkWidget *w)
{
	return w->allocation.height;
}

#endif

#if GTK_MAJOR_VERSION <= 2 && GTK_MINOR_VERSION < 18
void gtk_widget_set_can_focus(GtkWidget *widget, gboolean can_focus)
{
	if (can_focus)
		GTK_WIDGET_SET_FLAGS(widget, GTK_CAN_FOCUS);
	else
		GTK_WIDGET_UNSET_FLAGS(widget, GTK_CAN_FOCUS);
}
#endif
