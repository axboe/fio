#include <gtk/gtk.h>

GtkWidget *new_combo_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_combo_box_new_text();
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

	return entry;
}

GtkWidget *new_info_entry_in_frame(GtkWidget *box, const char *label)
{
	GtkWidget *entry, *frame;

	frame = gtk_frame_new(label);
	entry = gtk_entry_new();
	gtk_entry_set_editable(GTK_ENTRY(entry), 0);
	gtk_box_pack_start(GTK_BOX(box), frame, TRUE, TRUE, 3);
	gtk_container_add(GTK_CONTAINER(frame), entry);

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
