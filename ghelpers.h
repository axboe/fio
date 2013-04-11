#ifndef GFIO_HELPERS_H
#define GFIO_HELPERS_H

GtkWidget *new_combo_entry_in_frame(GtkWidget *box, const char *label);
GtkWidget *new_info_entry_in_frame(GtkWidget *box, const char *label);
GtkWidget *new_info_label_in_frame(GtkWidget *box, const char *label);
GtkWidget *new_info_entry_in_frame_rgb(GtkWidget *box, const char *label,
					gfloat r, gfloat g, gfloat b);
GtkWidget *create_spinbutton(GtkWidget *hbox, double min, double max, double defval);
void label_set_int_value(GtkWidget *entry, unsigned int val);
void entry_set_int_value(GtkWidget *entry, unsigned int val);

GtkWidget *get_scrolled_window(gint border_width);

struct multitext_widget {
	GtkWidget *entry;
	char **text;
	unsigned int cur_text;
	unsigned int max_text;
};

void multitext_add_entry(struct multitext_widget *mt, const char *text);
void multitext_set_entry(struct multitext_widget *mt, unsigned int index);
void multitext_update_entry(struct multitext_widget *mt, unsigned int index,
			    const char *text);
void multitext_free(struct multitext_widget *mt);

#define ALIGN_LEFT 1
#define ALIGN_RIGHT 2
#define INVISIBLE 4
#define UNSORTABLE 8

GtkTreeViewColumn *tree_view_column(GtkWidget *tree_view, int index, const char *title, unsigned int flags);

#endif
