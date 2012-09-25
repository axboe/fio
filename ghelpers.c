#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include "gcompat.h"
#include "ghelpers.h"

GtkWidget *new_combo_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_combo_box_text_new();
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

	return entry;
}

GtkWidget *new_info_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_entry_new();
	gtk_editable_set_editable(GTK_EDITABLE(entry), 0);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

	return entry;
}

static void fill_color_from_rgb(GdkColor *c, gfloat r, gfloat g, gfloat b)
{
	gint R, G, B;
	gchar tmp[8];

	memset(c, 0, sizeof(*c));
	R = r * 255;
	G = g * 255;
	B = b * 255;
	snprintf(tmp, sizeof(tmp), "#%02x%02x%02x", R, G, B);
	gdk_color_parse(tmp, c);
}

GtkWidget *new_info_entry_in_frame_rgb(GtkWidget *box, const char *label,
					gfloat r, gfloat g, gfloat b)
{
	GtkWidget *entry;
	GdkColor c;

	entry = new_info_entry_in_frame(box, label);
	fill_color_from_rgb(&c, r, g, b);
	gtk_widget_modify_text(entry, GTK_STATE_NORMAL, &c);
	return entry;
}

GtkWidget *new_info_label_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *label_widget;
	GtkWidget *frame;

	frame = gtk_frame_new(label);
	label_widget = gtk_label_new(NULL);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), label_widget);

	return label_widget;
}

GtkWidget *create_spinbutton(GtkWidget *hbox, double min, double max, double defval)
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

void label_set_int_value(GtkWidget *entry, unsigned int val)
{
	char tmp[80];

	sprintf(tmp, "%u", val);
	gtk_label_set_text(GTK_LABEL(entry), tmp);
}

void entry_set_int_value(GtkWidget *entry, unsigned int val)
{
	char tmp[80];

	sprintf(tmp, "%u", val);
	gtk_entry_set_text(GTK_ENTRY(entry), tmp);
}

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
	gtk_tree_view_column_set_expand(col, TRUE);
	gtk_tree_view_column_add_attribute(col, renderer, "text", index);
	g_object_set(G_OBJECT(renderer), "alignment", align, NULL);
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

void multitext_add_entry(struct multitext_widget *mt, const char *text)
{
	mt->text = realloc(mt->text, (mt->max_text + 1) * sizeof(char *));
	mt->text[mt->max_text] = strdup(text);
	mt->max_text++;
}

void multitext_set_entry(struct multitext_widget *mt, unsigned int index)
{
	if (index >= mt->max_text)
		return;
	if (!mt->text || !mt->text[index])
		return;

	mt->cur_text = index;
	gtk_entry_set_text(GTK_ENTRY(mt->entry), mt->text[index]);
}

void multitext_update_entry(struct multitext_widget *mt, unsigned int index,
			    const char *text)
{
	if (!mt->text)
		return;

	if (mt->text[index])
		free(mt->text[index]);

	mt->text[index] = strdup(text);
	if (mt->cur_text == index)
		gtk_entry_set_text(GTK_ENTRY(mt->entry), mt->text[index]);
}

void multitext_free(struct multitext_widget *mt)
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

GtkWidget *get_scrolled_window(gint border_width)
{
	GtkWidget *scroll;

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll), border_width);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	return scroll;
}
