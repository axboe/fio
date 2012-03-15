#ifndef GFIO_HELPERS_H
#define GFIO_HELPERS_H

GtkWidget *new_combo_entry_in_frame(GtkWidget *box, const char *label);
GtkWidget *new_info_entry_in_frame(GtkWidget *box, const char *label);
GtkWidget *new_info_label_in_frame(GtkWidget *box, const char *label);
GtkWidget *create_spinbutton(GtkWidget *hbox, double min, double max, double defval);
void label_set_int_value(GtkWidget *entry, unsigned int val);
void entry_set_int_value(GtkWidget *entry, unsigned int val);

#endif
