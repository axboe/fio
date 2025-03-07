#include <locale.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <cairo.h>
#include <gtk/gtk.h>

#include "fio.h"
#include "gfio.h"
#include "ghelpers.h"
#include "gerror.h"
#include "parse.h"
#include "optgroup.h"

struct gopt {
	GtkWidget *box;
	unsigned int opt_index;
	unsigned int opt_type;
	gulong sig_handler;
	struct gopt_job_view *gjv;
	struct flist_head changed_list;
};

struct gopt_combo {
	struct gopt gopt;
	GtkWidget *combo;
};

struct gopt_int {
	struct gopt gopt;
	unsigned long long lastval;
	GtkWidget *spin;
};

struct gopt_bool {
	struct gopt gopt;
	GtkWidget *check;
};

struct gopt_str {
	struct gopt gopt;
	GtkWidget *entry;
};

struct gopt_str_val {
	struct gopt gopt;
	GtkWidget *spin;
	GtkWidget *combo;
	unsigned int maxindex;
};

#define GOPT_RANGE_SPIN	4

struct gopt_range {
	struct gopt gopt;
	GtkWidget *spins[GOPT_RANGE_SPIN];
};

struct gopt_str_multi {
	struct gopt gopt;
	GtkWidget *checks[PARSE_MAX_VP];
};

enum {
	GOPT_COMBO_INT = 1,
	GOPT_COMBO_STR,
	GOPT_INT,
	GOPT_BOOL,
	GOPT_STR,
	GOPT_STR_VAL,
	GOPT_RANGE,
	GOPT_STR_MULTI,
};

struct gopt_frame_widget {
	GtkWidget *vbox[2];
	unsigned int nr;
};

struct gopt_job_view {
	struct gopt_frame_widget g_widgets[__FIO_OPT_G_NR];
	GtkWidget *vboxes[__FIO_OPT_C_NR];
	struct gopt *gopts[FIO_MAX_OPTS];
	GtkWidget *dialog;
	GtkWidget *job_combo;
	struct gfio_client *client;
	struct flist_head changed_list;
	struct thread_options *o;
	int in_job_switch;
};

static GNode *gopt_dep_tree;

static GtkWidget *gopt_get_group_frame(struct gopt_job_view *gjv,
				       GtkWidget *box, uint64_t groupmask)
{
	uint64_t mask, group;
	const struct opt_group *og;
	GtkWidget *frame, *hbox;
	struct gopt_frame_widget *gfw;

	if (!groupmask)
		return 0;

	mask = groupmask;
	og = opt_group_cat_from_mask(&mask);
	if (!og)
		return NULL;

	group = ffz64(~groupmask);
	gfw = &gjv->g_widgets[group];
	if (!gfw->vbox[0]) {
		frame = gtk_frame_new(og->name);
		gtk_box_pack_start(GTK_BOX(box), frame, FALSE, FALSE, 3);
		hbox = gtk_hbox_new(FALSE, 0);
		gtk_container_add(GTK_CONTAINER(frame), hbox);
		gfw->vbox[0] = gtk_vbox_new(TRUE, 5);
		gfw->vbox[1] = gtk_vbox_new(TRUE, 5);
		gtk_box_pack_start(GTK_BOX(hbox), gfw->vbox[0], TRUE, TRUE, 5);
		gtk_box_pack_start(GTK_BOX(hbox), gfw->vbox[1], TRUE, TRUE, 5);
	}

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_box_pack_start(GTK_BOX(gfw->vbox[gfw->nr++ & 1]), hbox, FALSE, FALSE, 5);
	return hbox;
}

/*
 * Mark children as invisible, if needed.
 */
static void gopt_set_children_visible(struct gopt_job_view *gjv,
				      struct fio_option *parent,
				      gboolean visible)
{
	GNode *child, *node;

	if (parent->hide_on_set)
		visible = !visible;

	node = g_node_find(gopt_dep_tree, G_IN_ORDER, G_TRAVERSE_ALL, parent);
	child = g_node_first_child(node);
	while (child) {
		struct fio_option *o = child->data;
		struct gopt *g = o->gui_data;
		GtkWidget *widget = g->box;

		/*
		 * Recurse into child, if it also has children
		 */
		if (g_node_n_children(child))
			gopt_set_children_visible(gjv, o, visible);

		gtk_widget_set_sensitive(widget, visible);
		child = g_node_next_sibling(child);
	}
}

static void gopt_mark_index(struct gopt_job_view *gjv, struct gopt *gopt,
			    unsigned int idx, int type)
{
	INIT_FLIST_HEAD(&gopt->changed_list);

	assert(!gjv->gopts[idx]);
	gopt->opt_index = idx;
	gopt->opt_type = type;
	gopt->gjv = gjv;
	gjv->gopts[idx] = gopt;
}

static void gopt_dialog_update_apply_button(struct gopt_job_view *gjv)
{
	GtkDialog *dialog = GTK_DIALOG(gjv->dialog);
	gboolean set;

	set = !flist_empty(&gjv->changed_list);
	gtk_dialog_set_response_sensitive(dialog, GTK_RESPONSE_APPLY, set);

	if (set) {
		gtk_widget_set_sensitive(gjv->job_combo, 0);
		gtk_widget_set_tooltip_text(gjv->job_combo, "Apply option changes before switching to a new job");
	} else {
		gtk_widget_set_sensitive(gjv->job_combo, 1);
		gtk_widget_set_tooltip_text(gjv->job_combo, "Change current job");
	}
}

static void gopt_changed(struct gopt *gopt)
{
	struct gopt_job_view *gjv = gopt->gjv;

	if (gjv->in_job_switch)
		return;

	/*
	 * Add to changed list. This also prevents the option from being
	 * freed when the widget is destroyed.
	 */
	if (flist_empty(&gopt->changed_list)) {
		flist_add_tail(&gopt->changed_list, &gjv->changed_list);
		gopt_dialog_update_apply_button(gjv);
	}
}

static void gopt_str_changed(GtkEntry *entry, gpointer data)
{
	struct gopt_str *s = (struct gopt_str *) data;
	struct fio_option *o = &fio_options[s->gopt.opt_index];
	const gchar *text;
	int set;

	gopt_changed(&s->gopt);

	text = gtk_entry_get_text(GTK_ENTRY(s->entry));
	set = strcmp(text, "") != 0;

	gopt_set_children_visible(s->gopt.gjv, o, set);
}

static void gopt_str_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_str *s = (struct gopt_str *) data;

	free(s);
	gtk_widget_destroy(w);
}

static void gopt_str_store_set_val(struct gopt_str *s, const char *text)
{
	if (text)
		gtk_entry_set_text(GTK_ENTRY(s->entry), text);
}

static struct gopt *gopt_new_str_store(struct gopt_job_view *gjv,
				       struct fio_option *o, const char *text,
				       unsigned int idx)
{
	struct gopt_str *s;
	GtkWidget *label;

	s = calloc(1, sizeof(*s));

	s->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	s->entry = gtk_entry_new();
	gopt_mark_index(gjv, &s->gopt, idx, GOPT_STR);
	gtk_editable_set_editable(GTK_EDITABLE(s->entry), 1);

	if (text)
		gopt_str_store_set_val(s, text);
	else if (o->def)
		gopt_str_store_set_val(s, o->def);

	s->gopt.sig_handler = g_signal_connect(G_OBJECT(s->entry), "changed", G_CALLBACK(gopt_str_changed), s);
	g_signal_connect(G_OBJECT(s->entry), "destroy", G_CALLBACK(gopt_str_destroy), s);

	gtk_box_pack_start(GTK_BOX(s->gopt.box), s->entry, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(s->gopt.box), label, FALSE, FALSE, 0);
	return &s->gopt;
}

static void gopt_combo_changed(GtkComboBox *box, gpointer data)
{
	struct gopt_combo *c = (struct gopt_combo *) data;
	struct fio_option *o = &fio_options[c->gopt.opt_index];
	unsigned int index;

	gopt_changed(&c->gopt);

	index = gtk_combo_box_get_active(GTK_COMBO_BOX(c->combo));

	gopt_set_children_visible(c->gopt.gjv, o, index);
}

static void gopt_combo_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_combo *c = (struct gopt_combo *) data;

	free(c);
	gtk_widget_destroy(w);
}

static struct gopt_combo *__gopt_new_combo(struct gopt_job_view *gjv,
					   struct fio_option *o,
					   unsigned int idx, int type)
{
	struct gopt_combo *c;
	GtkWidget *label;

	c = calloc(1, sizeof(*c));

	c->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	c->combo = gtk_combo_box_text_new();
	gopt_mark_index(gjv, &c->gopt, idx, type);
	g_signal_connect(G_OBJECT(c->combo), "destroy", G_CALLBACK(gopt_combo_destroy), c);

	gtk_box_pack_start(GTK_BOX(c->gopt.box), c->combo, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(c->gopt.box), label, FALSE, FALSE, 0);

	return c;
}

static void gopt_combo_str_set_val(struct gopt_combo *c, const char *text)
{
	struct fio_option *o = &fio_options[c->gopt.opt_index];
	struct value_pair *vp;
	int i;

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		if (!strcmp(vp->ival, text)) {
			gtk_combo_box_set_active(GTK_COMBO_BOX(c->combo), i);
			break;
		}
		vp++;
		i++;
	}
}

static struct gopt *gopt_new_combo_str(struct gopt_job_view *gjv,
				       struct fio_option *o, const char *text,
				       unsigned int idx)
{
	struct gopt_combo *c;
	struct value_pair *vp;
	int i, active = 0;

	c = __gopt_new_combo(gjv, o, idx, GOPT_COMBO_STR);

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->combo), vp->ival);
		if (o->def && !strcmp(vp->ival, o->def))
			active = i;
		vp++;
		i++;
	}

	gtk_combo_box_set_active(GTK_COMBO_BOX(c->combo), active);
	if (text)
		gopt_combo_str_set_val(c, text);
	c->gopt.sig_handler = g_signal_connect(G_OBJECT(c->combo), "changed", G_CALLBACK(gopt_combo_changed), c);
	return &c->gopt;
}

static void gopt_combo_int_set_val(struct gopt_combo *c, unsigned int ip)
{
	struct fio_option *o = &fio_options[c->gopt.opt_index];
	struct value_pair *vp;
	int i;

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		if (vp->oval == ip) {
			gtk_combo_box_set_active(GTK_COMBO_BOX(c->combo), i);
			break;
		}
		vp++;
		i++;
	}
}

static struct gopt *gopt_new_combo_int(struct gopt_job_view *gjv,
				       struct fio_option *o, unsigned int *ip,
				       unsigned int idx)
{
	struct gopt_combo *c;
	struct value_pair *vp;
	int i, active = 0;

	c = __gopt_new_combo(gjv, o, idx, GOPT_COMBO_INT);

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(c->combo), vp->ival);
		if (ip && vp->oval == *ip)
			active = i;
		vp++;
		i++;
	}

	gtk_combo_box_set_active(GTK_COMBO_BOX(c->combo), active);
	if (ip)
		gopt_combo_int_set_val(c, *ip);
	c->gopt.sig_handler = g_signal_connect(G_OBJECT(c->combo), "changed", G_CALLBACK(gopt_combo_changed), c);
	return &c->gopt;
}

static void gopt_str_multi_toggled(GtkToggleButton *button, gpointer data)
{
	struct gopt_str_multi *m = (struct gopt_str_multi *) data;

	gopt_changed(&m->gopt);
}

static void gopt_str_multi_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_str_multi *m = (struct gopt_str_multi *) data;

	free(m);
	gtk_widget_destroy(w);
}

static void gopt_str_multi_set_val(struct gopt_str_multi *m, int val)
{
}

static struct gopt *gopt_new_str_multi(struct gopt_job_view *gjv,
				       struct fio_option *o, unsigned int idx)
{
	struct gopt_str_multi *m;
	struct value_pair *vp;
	GtkWidget *frame, *hbox;
	int i;

	m = calloc(1, sizeof(*m));
	m->gopt.box = gtk_hbox_new(FALSE, 3);
	gopt_mark_index(gjv, &m->gopt, idx, GOPT_STR_MULTI);

	if (!o->lname)
		frame = gtk_frame_new(o->name);
	else
		frame = gtk_frame_new(o->lname);
	gtk_box_pack_start(GTK_BOX(m->gopt.box), frame, FALSE, FALSE, 3);

	hbox = gtk_hbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(frame), hbox);

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		m->checks[i] = gtk_check_button_new_with_label(vp->ival);
		gtk_widget_set_tooltip_text(m->checks[i], vp->help);
		gtk_box_pack_start(GTK_BOX(hbox), m->checks[i], FALSE, FALSE, 3);
		g_signal_connect(G_OBJECT(m->checks[i]), "toggled", G_CALLBACK(gopt_str_multi_toggled), m);
		vp++;
		i++;
	}

	gopt_str_multi_set_val(m, 0);
	g_signal_connect(G_OBJECT(m->gopt.box), "destroy", G_CALLBACK(gopt_str_multi_destroy), m);
	return &m->gopt;
}

static void gopt_int_changed(GtkSpinButton *spin, gpointer data)
{
	struct gopt_int *i = (struct gopt_int *) data;
	struct fio_option *o = &fio_options[i->gopt.opt_index];
	GtkAdjustment *adj;
	int value, delta;

	gopt_changed(&i->gopt);

	adj = gtk_spin_button_get_adjustment(spin);
	value = gtk_adjustment_get_value(adj);
	delta = value - i->lastval;
	i->lastval = value;

	if (o->inv_opt) {
		struct gopt *b_inv = o->inv_opt->gui_data;
		struct gopt_int *i_inv = container_of(b_inv, struct gopt_int, gopt);
		int cur_val;

		assert(o->type == o->inv_opt->type);

		cur_val = gtk_spin_button_get_value(GTK_SPIN_BUTTON(i_inv->spin));
		cur_val -= delta;
		g_signal_handler_block(G_OBJECT(i_inv->spin), i_inv->gopt.sig_handler);
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(i_inv->spin), cur_val);
		g_signal_handler_unblock(G_OBJECT(i_inv->spin), i_inv->gopt.sig_handler);
	}
}

static void gopt_int_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_int *i = (struct gopt_int *) data;

	free(i);
	gtk_widget_destroy(w);
}

static void gopt_int_set_val(struct gopt_int *i, unsigned long long p)
{
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(i->spin), p);
	i->lastval = p;
}

static struct gopt_int *__gopt_new_int(struct gopt_job_view *gjv,
				       struct fio_option *o,
				       unsigned long long *p, unsigned int idx)
{
	unsigned long long defval;
	struct gopt_int *i;
	guint maxval, interval;
	GtkWidget *label;

	i = calloc(1, sizeof(*i));
	i->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	maxval = o->maxval;
	if (!maxval)
		maxval = UINT_MAX;

	defval = 0;
	if (p)
		defval = *p;
	else if (o->def) {
		long long val;

		check_str_bytes(o->def, &val, o);
		defval = val;
	}

	interval = 1.0;
	if (o->interval)
		interval = o->interval;

	i->spin = gtk_spin_button_new_with_range(o->minval, maxval, interval);
	gopt_mark_index(gjv, &i->gopt, idx, GOPT_INT);
	gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(i->spin), GTK_UPDATE_IF_VALID);
	if (p)
		gopt_int_set_val(i, *p);
	else
		gopt_int_set_val(i, defval);
	i->gopt.sig_handler = g_signal_connect(G_OBJECT(i->spin), "value-changed", G_CALLBACK(gopt_int_changed), i);
	g_signal_connect(G_OBJECT(i->spin), "destroy", G_CALLBACK(gopt_int_destroy), i);

	gtk_box_pack_start(GTK_BOX(i->gopt.box), i->spin, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(i->gopt.box), label, FALSE, FALSE, 0);

	return i;
}

static struct gopt *gopt_new_int(struct gopt_job_view *gjv,
				 struct fio_option *o, unsigned int *ip,
				 unsigned int idx)
{
	unsigned long long ullp;
	struct gopt_int *i;

	if (ip) {
		ullp = *ip;
		i = __gopt_new_int(gjv, o, &ullp, idx);
	} else
		i = __gopt_new_int(gjv, o, NULL, idx);

	return &i->gopt;
}

static struct gopt *gopt_new_ullong(struct gopt_job_view *gjv,
				    struct fio_option *o, unsigned long long *p,
				    unsigned int idx)
{
	struct gopt_int *i;

	i = __gopt_new_int(gjv, o, p, idx);
	return &i->gopt;
}

static void gopt_bool_toggled(GtkToggleButton *button, gpointer data)
{
	struct gopt_bool *b = (struct gopt_bool *) data;
	struct fio_option *o = &fio_options[b->gopt.opt_index];
	gboolean set;

	gopt_changed(&b->gopt);

	set = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(b->check));

	if (o->inv_opt) {
		struct gopt *g_inv = o->inv_opt->gui_data;
		struct gopt_bool *b_inv = container_of(g_inv, struct gopt_bool, gopt);

		assert(o->type == o->inv_opt->type);

		g_signal_handler_block(G_OBJECT(b_inv->check), b_inv->gopt.sig_handler);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b_inv->check), !set);
		g_signal_handler_unblock(G_OBJECT(b_inv->check), b_inv->gopt.sig_handler);
	}

	gopt_set_children_visible(b->gopt.gjv, o, set);
}

static void gopt_bool_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_bool *b = (struct gopt_bool *) data;

	free(b);
	gtk_widget_destroy(w);
}

static void gopt_bool_set_val(struct gopt_bool *b, unsigned int val)
{
	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b->check), val);
}

static struct gopt *gopt_new_bool(struct gopt_job_view *gjv,
				  struct fio_option *o, unsigned int *val,
				  unsigned int idx)
{
	struct gopt_bool *b;
	GtkWidget *label;
	int defstate = 0;

	b = calloc(1, sizeof(*b));
	b->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	b->check = gtk_check_button_new();
	gopt_mark_index(gjv, &b->gopt, idx, GOPT_BOOL);
	if (o->def && !strcmp(o->def, "1"))
		defstate = 1;

	if (o->neg)
		defstate = !defstate;

	if (val)
		gopt_bool_set_val(b, *val);
	else
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b->check), defstate);
	b->gopt.sig_handler = g_signal_connect(G_OBJECT(b->check), "toggled", G_CALLBACK(gopt_bool_toggled), b);
	g_signal_connect(G_OBJECT(b->check), "destroy", G_CALLBACK(gopt_bool_destroy), b);

	gtk_box_pack_start(GTK_BOX(b->gopt.box), b->check, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(b->gopt.box), label, FALSE, FALSE, 0);
	return &b->gopt;
}

/*
 * These are paired 0/1 and 2/3. 0/2 are min values, 1/3 are max values.
 * If the max is made smaller than min, adjust min down.
 * If the min is made larger than max, adjust the max.
 */
static void range_value_changed(GtkSpinButton *spin, gpointer data)
{
	struct gopt_range *r = (struct gopt_range *) data;
	int changed = -1, i;
	gint val, mval;

	gopt_changed(&r->gopt);

	for (i = 0; i < GOPT_RANGE_SPIN; i++) {
		if (GTK_SPIN_BUTTON(r->spins[i]) == spin) {
			changed = i;
			break;
		}
	}

	assert(changed != -1);

	/*
	 * Min changed
	 */
	if (changed == 0 || changed == 2) {
		GtkWidget *mspin = r->spins[changed + 1];

		val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(r->spins[changed]));
		mval = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(mspin));
		if (val > mval)
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(mspin), val);
	} else {
		GtkWidget *mspin = r->spins[changed - 1];

		val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(r->spins[changed]));
		mval = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(mspin));
		if (val < mval)
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(mspin), val);
	}
}

static void gopt_range_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_range *r = (struct gopt_range *) data;

	free(r);
	gtk_widget_destroy(w);
}

static void gopt_int_range_set_val(struct gopt_range *r, unsigned int *vals)
{
	int i;

	for (i = 0; i < GOPT_RANGE_SPIN; i++)
		gtk_spin_button_set_value(GTK_SPIN_BUTTON(r->spins[i]), vals[i]);
}

static struct gopt *gopt_new_int_range(struct gopt_job_view *gjv,
				       struct fio_option *o, unsigned int **ip,
				       unsigned int idx)
{
	struct gopt_range *r;
	GtkWidget *label;
	guint interval;
	unsigned int defvals[GOPT_RANGE_SPIN];
	gint maxval;
	int i;

	r = calloc(1, sizeof(*r));
	r->gopt.box = gtk_hbox_new(FALSE, 3);
	gopt_mark_index(gjv, &r->gopt, idx, GOPT_RANGE);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	maxval = o->maxval;
	if (!maxval)
		maxval = INT_MAX;

	memset(defvals, 0, sizeof(defvals));
	if (o->def) {
		long long val;

		check_str_bytes(o->def, &val, o);
		for (i = 0; i < GOPT_RANGE_SPIN; i++)
			defvals[i] = val;
	}

	interval = 1.0;
	if (o->interval)
		interval = o->interval;

	for (i = 0; i < GOPT_RANGE_SPIN; i++) {
		r->spins[i] = gtk_spin_button_new_with_range(o->minval, maxval, interval);
		gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(r->spins[i]), GTK_UPDATE_IF_VALID);
		gtk_box_pack_start(GTK_BOX(r->gopt.box), r->spins[i], FALSE, FALSE, 0);
	}

	if (ip)
		gopt_int_range_set_val(r, *ip);
	else
		gopt_int_range_set_val(r, defvals);

	for (i = 0; i < GOPT_RANGE_SPIN; i++)
		g_signal_connect(G_OBJECT(r->spins[i]), "value-changed", G_CALLBACK(range_value_changed), r);

	gtk_box_pack_start(GTK_BOX(r->gopt.box), label, FALSE, FALSE, 0);
	g_signal_connect(G_OBJECT(r->gopt.box), "destroy", G_CALLBACK(gopt_range_destroy), r);
	return &r->gopt;
}

static void gopt_str_val_destroy(GtkWidget *w, gpointer data)
{
	struct gopt_str_val *g = (struct gopt_str_val *) data;

	free(g);
	gtk_widget_destroy(w);
}

static void gopt_str_val_spin_wrapped(GtkSpinButton *spin, gpointer data)
{
	struct gopt_str_val *g = (struct gopt_str_val *) data;
	unsigned int val;
	GtkAdjustment *adj;
	gint index;

	adj = gtk_spin_button_get_adjustment(spin);
	val = gtk_adjustment_get_value(adj);

	/*
	 * Can't rely on exact value, as fast changes increment >= 1
	 */
	if (!val) {
		index = gtk_combo_box_get_active(GTK_COMBO_BOX(g->combo));
		if (index + 1 <= g->maxindex) {
			val = 1;
			gtk_combo_box_set_active(GTK_COMBO_BOX(g->combo), ++index);
		} else
			val = 1023;
		gtk_spin_button_set_value(spin, val);
	} else {
		index = gtk_combo_box_get_active(GTK_COMBO_BOX(g->combo));
		if (index) {
			gtk_combo_box_set_active(GTK_COMBO_BOX(g->combo), --index);
			gtk_spin_button_set_value(spin, 1023);
		} else
			gtk_spin_button_set_value(spin, 0);
	}
}

static void gopt_str_val_changed(GtkSpinButton *spin, gpointer data)
{
	struct gopt_str_val *g = (struct gopt_str_val *) data;

	gopt_changed(&g->gopt);
}

static void gopt_str_val_set_val(struct gopt_str_val *g, unsigned long long val)
{
	int i = 0;

	do {
		if (!val || (val % 1024))
			break;

		i++;
		val /= 1024;
	} while (1);

	gtk_spin_button_set_value(GTK_SPIN_BUTTON(g->spin), val);
	gtk_combo_box_set_active(GTK_COMBO_BOX(g->combo), i);
}

static struct gopt *gopt_new_str_val(struct gopt_job_view *gjv,
				     struct fio_option *o,
				     unsigned long long *p, unsigned int idx)
{
	struct gopt_str_val *g;
	const gchar *postfix[] = { "B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB" };
	GtkWidget *label;
	int i;

	g = calloc(1, sizeof(*g));
	g->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);
	gopt_mark_index(gjv, &g->gopt, idx, GOPT_STR_VAL);

	g->spin = gtk_spin_button_new_with_range(0.0, 1023.0, 1.0);
	gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(g->spin), GTK_UPDATE_IF_VALID);
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(g->spin), 0);
	gtk_spin_button_set_wrap(GTK_SPIN_BUTTON(g->spin), 1);
	gtk_box_pack_start(GTK_BOX(g->gopt.box), g->spin, FALSE, FALSE, 0);
	g_signal_connect(G_OBJECT(g->spin), "wrapped", G_CALLBACK(gopt_str_val_spin_wrapped), g);
	g_signal_connect(G_OBJECT(g->spin), "changed", G_CALLBACK(gopt_str_val_changed), g);

	g->combo = gtk_combo_box_text_new();
	i = 0;
	while (strlen(postfix[i])) {
		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(g->combo), postfix[i]);
		i++;
	}
	g->maxindex = i - 1;
	gtk_combo_box_set_active(GTK_COMBO_BOX(g->combo), 0);
	gtk_box_pack_start(GTK_BOX(g->gopt.box), g->combo, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(g->gopt.box), label, FALSE, FALSE, 3);

	if (p)
		gopt_str_val_set_val(g, *p);

	g_signal_connect(G_OBJECT(g->combo), "changed", G_CALLBACK(gopt_str_val_changed), g);

	g_signal_connect(G_OBJECT(g->gopt.box), "destroy", G_CALLBACK(gopt_str_val_destroy), g);
	return &g->gopt;
}

static void gopt_set_option(struct gopt_job_view *gjv, struct fio_option *o,
			    struct gopt *gopt, struct thread_options *to)
{
	switch (o->type) {
	case FIO_OPT_STR_VAL: {
		unsigned long long *ullp = NULL;
		struct gopt_str_val *g;

		if (o->off1)
			ullp = td_var(to, o, o->off1);

		g = container_of(gopt, struct gopt_str_val, gopt);
		if (ullp)
			gopt_str_val_set_val(g, *ullp);
		break;
		}
	case FIO_OPT_STR_VAL_TIME: {
		unsigned long long *ullp = NULL;
		struct gopt_int *i;

		if (o->off1)
			ullp = td_var(to, o, o->off1);

		i = container_of(gopt, struct gopt_int, gopt);
		if (ullp)
			gopt_int_set_val(i, *ullp);
		break;
		}
	case FIO_OPT_INT:
		if (o->posval[0].ival) {
			unsigned int *ip = NULL;
			struct gopt_combo *c;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			c = container_of(gopt, struct gopt_combo, gopt);
			if (ip)
				gopt_combo_int_set_val(c, *ip);
		} else {
			unsigned int *ip = NULL;
			struct gopt_int *i;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			i = container_of(gopt, struct gopt_int, gopt);
			if (ip)
				gopt_int_set_val(i, *ip);
		}
		break;
	case FIO_OPT_STR_SET:
	case FIO_OPT_BOOL: {
		unsigned int *ip = NULL;
		struct gopt_bool *b;

		if (o->off1)
			ip = td_var(to, o, o->off1);

		b = container_of(gopt, struct gopt_bool, gopt);
		if (ip)
			gopt_bool_set_val(b, *ip);
		break;
		}
	case FIO_OPT_STR: {
		if (o->posval[0].ival) {
			unsigned int *ip = NULL;
			struct gopt_combo *c;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			c = container_of(gopt, struct gopt_combo, gopt);
			if (ip)
				gopt_combo_int_set_val(c, *ip);
		} else {
			struct gopt_str *s;
			char *text = NULL;

			if (o->off1) {
				char **p = td_var(to, o, o->off1);

				text = *p;
			}

			s = container_of(gopt, struct gopt_str, gopt);
			gopt_str_store_set_val(s, text);
		}

		break;
		}
	case FIO_OPT_STR_STORE: {
		struct gopt_combo *c;
		char *text = NULL;

		if (o->off1) {
			char **p = td_var(to, o, o->off1);
			text = *p;
		}

		if (!o->posval[0].ival) {
			struct gopt_str *s;

			s = container_of(gopt, struct gopt_str, gopt);
			gopt_str_store_set_val(s, text);
			break;
		}

		c = container_of(gopt, struct gopt_combo, gopt);
		if (text)
			gopt_combo_str_set_val(c, text);
		break;
		}
	case FIO_OPT_STR_MULTI:
		/* HANDLE ME */
		break;
	case FIO_OPT_RANGE: {
		struct gopt_range *r;
		unsigned int *ip[4] = { td_var(to, o, o->off1),
					td_var(to, o, o->off2),
					td_var(to, o, o->off3),
					td_var(to, o, o->off4) };

		r = container_of(gopt, struct gopt_range, gopt);
		gopt_int_range_set_val(r, *ip);
		break;
		}
	/* still need to handle this one */
	case FIO_OPT_FLOAT_LIST:
		break;
	case FIO_OPT_DEPRECATED:
		break;
	default:
		printf("ignore type %u\n", o->type);
		break;
	}
}

static void gopt_add_option(struct gopt_job_view *gjv, GtkWidget *hbox,
			    struct fio_option *o, unsigned int opt_index,
			    struct thread_options *to)
{
	struct gopt *go = NULL;

	switch (o->type) {
	case FIO_OPT_STR_VAL: {
		unsigned long long *ullp = NULL;

		if (o->off1)
			ullp = td_var(to, o, o->off1);

		go = gopt_new_str_val(gjv, o, ullp, opt_index);
		break;
		}
	case FIO_OPT_STR_VAL_TIME: {
		unsigned long long *ullp = NULL;

		if (o->off1)
			ullp = td_var(to, o, o->off1);

		go = gopt_new_ullong(gjv, o, ullp, opt_index);
		break;
		}
	case FIO_OPT_INT:
		if (o->posval[0].ival) {
			unsigned int *ip = NULL;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			go = gopt_new_combo_int(gjv, o, ip, opt_index);
		} else {
			unsigned int *ip = NULL;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			go = gopt_new_int(gjv, o, ip, opt_index);
		}
		break;
	case FIO_OPT_STR_SET:
	case FIO_OPT_BOOL: {
		unsigned int *ip = NULL;

		if (o->off1)
			ip = td_var(to, o, o->off1);

		go = gopt_new_bool(gjv, o, ip, opt_index);
		break;
		}
	case FIO_OPT_STR: {
		if (o->posval[0].ival) {
			unsigned int *ip = NULL;

			if (o->off1)
				ip = td_var(to, o, o->off1);

			go = gopt_new_combo_int(gjv, o, ip, opt_index);
		} else {
			/* TODO: usually ->cb, or unsigned int pointer */
			go = gopt_new_str_store(gjv, o, NULL, opt_index);
		}

		break;
		}
	case FIO_OPT_STR_STORE: {
		char *text = NULL;

		if (o->off1) {
			char **p = td_var(to, o, o->off1);
			text = *p;
		}

		if (!o->posval[0].ival) {
			go = gopt_new_str_store(gjv, o, text, opt_index);
			break;
		}

		go = gopt_new_combo_str(gjv, o, text, opt_index);
		break;
		}
	case FIO_OPT_STR_MULTI:
		go = gopt_new_str_multi(gjv, o, opt_index);
		break;
	case FIO_OPT_RANGE: {
		unsigned int *ip[4] = { td_var(to, o, o->off1),
					td_var(to, o, o->off2),
					td_var(to, o, o->off3),
					td_var(to, o, o->off4) };

		go = gopt_new_int_range(gjv, o, ip, opt_index);
		break;
		}
	/* still need to handle this one */
	case FIO_OPT_FLOAT_LIST:
		break;
	case FIO_OPT_DEPRECATED:
		break;
	default:
		printf("ignore type %u\n", o->type);
		break;
	}

	if (go) {
		GtkWidget *dest;

		if (o->help)
			gtk_widget_set_tooltip_text(go->box, o->help);

		o->gui_data = go;

		dest = gopt_get_group_frame(gjv, hbox, o->group);
		if (!dest)
			gtk_box_pack_start(GTK_BOX(hbox), go->box, FALSE, FALSE, 5);
		else
			gtk_box_pack_start(GTK_BOX(dest), go->box, FALSE, FALSE, 5);
	}
}

static void gopt_add_options(struct gopt_job_view *gjv,
			     struct thread_options *to)
{
	GtkWidget *hbox = NULL;
	int i;

	/*
	 * First add all options
	 */
	for (i = 0; fio_options[i].name; i++) {
		struct fio_option *o = &fio_options[i];
		uint64_t mask = o->category;
		const struct opt_group *og;

		while ((og = opt_group_from_mask(&mask)) != NULL) {
			GtkWidget *vbox = gjv->vboxes[ffz64(~og->mask)];

			hbox = gtk_hbox_new(FALSE, 3);
			gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
			gopt_add_option(gjv, hbox, o, i, to);
		}
	}
}

static void gopt_set_options(struct gopt_job_view *gjv,
			     struct thread_options *to)
{
	int i;

	for (i = 0; fio_options[i].name; i++) {
		struct fio_option *o = &fio_options[i];
		struct gopt *gopt = gjv->gopts[i];

		gopt_set_option(gjv, o, gopt, to);
	}
}

static GtkWidget *gopt_add_tab(GtkWidget *notebook, const char *name)
{
	GtkWidget *box, *vbox, *scroll;

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	vbox = gtk_vbox_new(FALSE, 3);
	box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), vbox);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll, gtk_label_new(name));
	return vbox;
}

static GtkWidget *gopt_add_group_tab(GtkWidget *notebook,
				     const struct opt_group *og)
{
	return gopt_add_tab(notebook, og->name);
}

static void gopt_add_group_tabs(GtkWidget *notebook, struct gopt_job_view *gjv)
{
	const struct opt_group *og;
	unsigned int i;

	i = 0;
	do {
		uint64_t mask = (1ULL << i);

		og = opt_group_from_mask(&mask);
		if (!og)
			break;
		gjv->vboxes[i] = gopt_add_group_tab(notebook, og);
		i++;
	} while (1);
}

static void gopt_handle_str_multi_changed(struct gopt_job_view *gjv,
					  struct gopt_str_multi *m,
					  struct fio_option *o)
{
	unsigned int *ip = td_var(gjv->o, o, o->off1);
	struct value_pair *vp;
	gboolean set;
	guint val = 0;
	int i;

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		if (!m->checks[i])
			break;
		set = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(m->checks[i]));
		if (set) {
			if (vp->orval)
				val |= vp->oval;
			else
				val = vp->oval;
		}
		i++;
		vp++;
	}

	if (o->off1)
		*ip = val;
}

static void gopt_handle_range_changed(struct gopt_job_view *gjv,
				      struct gopt_range *r,
				      struct fio_option *o)
{
	unsigned int *ip[4] = { td_var(gjv->o, o, o->off1),
				td_var(gjv->o, o, o->off2),
				td_var(gjv->o, o, o->off3),
				td_var(gjv->o, o, o->off4) };
	gint val;
	int i;

	for (i = 0; i < GOPT_RANGE_SPIN; i++) {
		val = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(r->spins[i]));
		*ip[i] = val;
	}
}

static void gopt_handle_str_val_changed(struct gopt_job_view *gjv,
					struct gopt_str_val *s,
					struct fio_option *o)
{
	unsigned long long *ullp = td_var(gjv->o, o, o->off1);
	GtkAdjustment *adj;
	gint index;

	if (!ullp)
		return;

	/*
	 * Numerical value
	 */
	adj = gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(s->spin));
	*ullp = gtk_adjustment_get_value(adj);

	/*
	 * Multiplier
	 */
	index = gtk_combo_box_get_active(GTK_COMBO_BOX(s->combo));
	while (index--)
		*ullp *= 1024ULL;
}

static void gopt_handle_str_changed(struct gopt_job_view *gjv,
				    struct gopt_str *s, struct fio_option *o)
{
	char **p = td_var(gjv->o, o, o->off1);

	if (*p)
		free(*p);

	*p = strdup(gtk_entry_get_text(GTK_ENTRY(s->entry)));
}

static void gopt_handle_bool_changed(struct gopt_job_view *gjv,
				     struct gopt_bool *b, struct fio_option *o)
{
	unsigned int *ip = td_var(gjv->o, o, o->off1);
	gboolean set;

	set = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(b->check));
	*ip = set;
}

static void gopt_handle_int_changed(struct gopt_job_view *gjv,
				    struct gopt_int *i, struct fio_option *o)
{
	unsigned int *ip = td_var(gjv->o, o, o->off1);
	GtkAdjustment *adj;
	guint val;

	adj = gtk_spin_button_get_adjustment(GTK_SPIN_BUTTON(i->spin));
	val = gtk_adjustment_get_value(adj);
	*ip = val;
}

static void gopt_handle_combo_str_changed(struct gopt_job_view *gjv,
					  struct gopt_combo *c,
					  struct fio_option *o)
{
	char **p = td_var(gjv->o, o, o->off1);

	if (*p)
		free(*p);

	*p = strdup(gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(c->combo)));
}

static void gopt_handle_combo_int_changed(struct gopt_job_view *gjv,
					  struct gopt_combo *c,
					  struct fio_option *o)
{
	unsigned int *ip = td_var(gjv->o, o, o->off1);
	gint index;

	index = gtk_combo_box_get_active(GTK_COMBO_BOX(c->combo));
	*ip = o->posval[index].oval;
}

static void gopt_handle_changed(struct gopt *gopt)
{
	struct fio_option *o = &fio_options[gopt->opt_index];
	struct gopt_job_view *gjv = gopt->gjv;

	switch (gopt->opt_type) {
	case GOPT_COMBO_INT: {
		struct gopt_combo *c;

		c = container_of(gopt, struct gopt_combo, gopt);
		gopt_handle_combo_int_changed(gjv, c, o);
		break;
		}
	case GOPT_COMBO_STR: {
		struct gopt_combo *c;

		c = container_of(gopt, struct gopt_combo, gopt);
		gopt_handle_combo_str_changed(gjv, c, o);
		break;
		}
	case GOPT_INT: {
		struct gopt_int *i;

		i = container_of(gopt, struct gopt_int, gopt);
		gopt_handle_int_changed(gjv, i, o);
		break;
		}
	case GOPT_BOOL: {
		struct gopt_bool *b;

		b = container_of(gopt, struct gopt_bool, gopt);
		gopt_handle_bool_changed(gjv, b, o);
		break;
		}
	case GOPT_STR: {
		struct gopt_str *s;

		s = container_of(gopt, struct gopt_str, gopt);
		gopt_handle_str_changed(gjv, s, o);
		break;
		}
	case GOPT_STR_VAL: {
		struct gopt_str_val *s;

		s = container_of(gopt, struct gopt_str_val, gopt);
		gopt_handle_str_val_changed(gjv, s, o);
		break;
		}
	case GOPT_RANGE: {
		struct gopt_range *r;

		r = container_of(gopt, struct gopt_range, gopt);
		gopt_handle_range_changed(gjv, r, o);
		break;
		}
	case GOPT_STR_MULTI: {
		struct gopt_str_multi *m;

		m = container_of(gopt, struct gopt_str_multi, gopt);
		gopt_handle_str_multi_changed(gjv, m, o);
		break;
		}
	default:
		log_err("gfio: bad option type: %d\n", gopt->opt_type);
		break;
	}
}

static void gopt_report_update_status(struct gopt_job_view *gjv)
{
	struct gfio_client *gc = gjv->client;
	char tmp[80];

	sprintf(tmp, "\nCompleted with error: %d\n", gc->update_job_status);
	gfio_report_info(gc->ge->ui, "Update job", tmp);
}

static int gopt_handle_changed_options(struct gopt_job_view *gjv)
{
	struct gfio_client *gc = gjv->client;
	struct flist_head *entry;
	uint64_t waitid = 0;
	struct gopt *gopt;
	int ret;

	flist_for_each(entry, &gjv->changed_list) {
		gopt = flist_entry(entry, struct gopt, changed_list);
		gopt_handle_changed(gopt);
	}

	gc->update_job_status = 0;
	gc->update_job_done = 0;

	ret = fio_client_update_options(gc->client, gjv->o, &waitid);
	if (ret)
		goto done;

	ret = fio_client_wait_for_reply(gc->client, waitid);
	if (ret)
		goto done;

	assert(gc->update_job_done);
	if (gc->update_job_status)
		goto done;

	while (!flist_empty(&gjv->changed_list)) {
		gopt = flist_first_entry(&gjv->changed_list, struct gopt, changed_list);
		flist_del_init(&gopt->changed_list);
	}

done:
	gopt_dialog_update_apply_button(gjv);
	return ret;
}

static gint gopt_dialog_cancel(gint response)
{
	switch (response) {
	case GTK_RESPONSE_NONE:
	case GTK_RESPONSE_REJECT:
	case GTK_RESPONSE_DELETE_EVENT:
	case GTK_RESPONSE_CANCEL:
	case GTK_RESPONSE_NO:
		return 1;
	default:
		return 0;
	}
}

static gint gopt_dialog_done(gint response)
{
	switch (response) {
	case GTK_RESPONSE_ACCEPT:
	case GTK_RESPONSE_OK:
	case GTK_RESPONSE_YES:
		return 1;
	default:
		return 0;
	}
}

static void gopt_handle_option_dialog(struct gopt_job_view *gjv)
{
	gint response;

	do {
		response = gtk_dialog_run(GTK_DIALOG(gjv->dialog));

		if (gopt_dialog_cancel(response) ||
		    gopt_dialog_done(response))
			break;

		/*
		 * Apply
		 */
		gopt_handle_changed_options(gjv);
		gopt_report_update_status(gjv);
	} while (1);

	if (gopt_dialog_cancel(response))
		return;

	gopt_handle_changed_options(gjv);
}

static void gopt_job_changed(GtkComboBox *box, gpointer data)
{
	struct gopt_job_view *gjv = (struct gopt_job_view *) data;
	struct gfio_client_options *gco = NULL;
	struct gfio_client *gc = gjv->client;
	struct flist_head *entry;
	gchar *job;

	/*
	 * The switch act should be sensitized appropriately, so that we
	 * never get here with modified options.
	 */
	if (!flist_empty(&gjv->changed_list)) {
		gfio_report_info(gc->ge->ui, "Internal Error", "Modified options on job switch.\nThat should not be possible!\n");
		return;
	}

	job = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(gjv->job_combo));
	flist_for_each(entry, &gc->o_list) {
		const char *name;

		gco = flist_entry(entry, struct gfio_client_options, list);
		name = gco->o.name;
		if (!name || !strlen(name))
			name = "Default job";

		if (!strcmp(name, job))
			break;

		gco = NULL;
	}

	if (!gco) {
		gfio_report_info(gc->ge->ui, "Internal Error", "Could not find job description.\nThat should not be possible!\n");
		return;
	}

	gjv->in_job_switch = 1;
	gopt_set_options(gjv, &gco->o);
	gjv->in_job_switch = 0;
}

void gopt_get_options_window(GtkWidget *window, struct gfio_client *gc)
{
	GtkWidget *dialog, *notebook, *vbox, *topvbox, *combo;
	struct gfio_client_options *gco;
	struct flist_head *entry;
	struct gopt_job_view *gjv;

	dialog = gtk_dialog_new_with_buttons("Fio options",
			GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_APPLY, GTK_RESPONSE_APPLY,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL);

	combo = gtk_combo_box_text_new();
	flist_for_each(entry, &gc->o_list) {
		struct thread_options *o;
		const char *name;

		gco = flist_entry(entry, struct gfio_client_options, list);
		o = &gco->o;
		name = o->name;
		if (!name || !strlen(name))
			name = "Default job";

		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), name);
	}
	gtk_combo_box_set_active(GTK_COMBO_BOX(combo), 0);

	gtk_widget_set_size_request(GTK_WIDGET(dialog), 1024, 768);

	topvbox = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
	gtk_box_pack_start(GTK_BOX(topvbox), combo, FALSE, FALSE, 5);

	vbox = gtk_vbox_new(TRUE, 5);
	gtk_box_pack_start(GTK_BOX(topvbox), vbox, TRUE, TRUE, 5);

	notebook = gtk_notebook_new();
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), 1);
	gtk_notebook_popup_enable(GTK_NOTEBOOK(notebook));
	gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 5);

	gjv = calloc(1, sizeof(*gjv));
	INIT_FLIST_HEAD(&gjv->changed_list);
	gco = flist_first_entry(&gc->o_list, struct gfio_client_options, list);
	gjv->o = &gco->o;
	gjv->dialog = dialog;
	gjv->client = gc;
	gjv->job_combo = combo;
	gopt_add_group_tabs(notebook, gjv);
	gopt_add_options(gjv, &gco->o);
	gopt_dialog_update_apply_button(gjv);

	g_signal_connect(G_OBJECT(combo), "changed", G_CALLBACK(gopt_job_changed), gjv);

	gtk_widget_show_all(dialog);

	gopt_handle_option_dialog(gjv);

	gtk_widget_destroy(dialog);
	free(gjv);
}

/*
 * Build n-ary option dependency tree
 */
void gopt_init(void)
{
	int i;

	gopt_dep_tree = g_node_new(NULL);

	for (i = 0; fio_options[i].name; i++) {
		struct fio_option *o = &fio_options[i];
		GNode *node, *nparent;

		/*
		 * Insert node with either the root parent, or an
		 * option parent.
		 */
		node = g_node_new(o);
		nparent = gopt_dep_tree;
		if (o->parent) {
			struct fio_option *parent;

			parent = fio_option_find(o->parent);
			nparent = g_node_find(gopt_dep_tree, G_IN_ORDER, G_TRAVERSE_ALL, parent);
			if (!nparent) {
				log_err("fio: did not find parent %s for opt %s\n", o->name, o->parent);
				nparent = gopt_dep_tree;
			}
		}

		g_node_insert(nparent, -1, node);
	}
}

void gopt_exit(void)
{
	g_node_destroy(gopt_dep_tree);
	gopt_dep_tree = NULL;
}
