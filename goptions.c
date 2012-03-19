#include <locale.h>
#include <malloc.h>
#include <string.h>

#include <glib.h>
#include <cairo.h>
#include <gtk/gtk.h>

#include "fio.h"
#include "gfio.h"
#include "ghelpers.h"
#include "parse.h"

struct gopt {
	GtkWidget *box;
	unsigned int opt_index;
	unsigned int opt_type;
};

struct gopt_combo {
	struct gopt gopt;
	GtkWidget *combo;
};

struct gopt_int {
	struct gopt gopt;
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

#define GOPT_RANGE_SPIN	4

struct gopt_range {
	struct gopt gopt;
	GtkWidget *spins[GOPT_RANGE_SPIN];
};

struct gopt_str_multi {
	struct gopt gopt;
	GtkWidget *checks[PARSE_MAX_VP];
};

static GtkWidget *gopt_widgets[FIO_MAX_OPTS];

struct gopt_frame_widget {
	GtkWidget *vbox[2];
	unsigned int nr;
};
static struct gopt_frame_widget gopt_g_widgets[__FIO_OPT_G_NR];

static GtkWidget *gopt_get_group_frame(GtkWidget *box, unsigned int groupmask)
{
	unsigned int mask, group;
	struct opt_group *og;
	GtkWidget *frame, *hbox;
	struct gopt_frame_widget *gfw;

	if (!groupmask)
		return 0;

	mask = groupmask;
	og = opt_group_cat_from_mask(&mask);
	if (!og)
		return NULL;

	group = ffz(~groupmask);
	gfw = &gopt_g_widgets[group];
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
static void gopt_set_children_visible(struct fio_option *parent, gboolean visible)
{
	struct fio_option *o;
	int i;

	/*
	 * This isn't super fast, but it should not be an issue. If it is, we
	 * can speed it up by caching the lookup at least. Or we can do it
	 * once, at init time.
	 */
	for (i = 0; fio_options[i].name; i++) {
		o = &fio_options[i];
		if (!o->parent || !o->hide)
			continue;

		if (strcmp(parent->name, o->parent))
			continue;

		if (gopt_widgets[i])
			gtk_widget_set_sensitive(gopt_widgets[i], visible);
	}
}

static void gopt_str_changed(GtkEntry *entry, gpointer data)
{
	struct gopt_str *s = (struct gopt_str *) data;
	struct fio_option *o = &fio_options[s->gopt.opt_index];
	const gchar *text;
	int set;

	text = gtk_entry_get_text(GTK_ENTRY(s->entry));
	set = strcmp(text, "") != 0;
	gopt_set_children_visible(o, set);
}

static void gopt_mark_index(struct gopt *gopt, unsigned int idx)
{
	assert(!gopt_widgets[idx]);
	gopt->opt_index = idx;
	gopt_widgets[idx] = gopt->box;
}

static struct gopt *gopt_new_str_store(struct fio_option *o, const char *text, unsigned int idx)
{
	struct gopt_str *s;
	GtkWidget *label;

	s = malloc(sizeof(*s));

	s->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	s->entry = gtk_entry_new();
	gopt_mark_index(&s->gopt, idx);
	if (text)
		gtk_entry_set_text(GTK_ENTRY(s->entry), text);
	gtk_entry_set_editable(GTK_ENTRY(s->entry), 1);
	g_signal_connect(GTK_OBJECT(s->entry), "changed", G_CALLBACK(gopt_str_changed), s);

	if (o->def)
		gtk_entry_set_text(GTK_ENTRY(s->entry), o->def);

	gtk_box_pack_start(GTK_BOX(s->gopt.box), s->entry, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(s->gopt.box), label, FALSE, FALSE, 0);
	return &s->gopt;
}

static void gopt_combo_changed(GtkComboBox *box, gpointer data)
{
	struct gopt_combo *c = (struct gopt_combo *) data;
	struct fio_option *o = &fio_options[c->gopt.opt_index];

	printf("combo %s changed\n", o->name);
}

static struct gopt_combo *__gopt_new_combo(struct fio_option *o, unsigned int idx)
{
	struct gopt_combo *c;
	GtkWidget *label;

	c = malloc(sizeof(*c));

	c->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	c->combo = gtk_combo_box_new_text();
	gopt_mark_index(&c->gopt, idx);
	g_signal_connect(GTK_OBJECT(c->combo), "changed", G_CALLBACK(gopt_combo_changed), c);

	gtk_box_pack_start(GTK_BOX(c->gopt.box), c->combo, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(c->gopt.box), label, FALSE, FALSE, 0);

	return c;
}

static struct gopt *gopt_new_combo_str(struct fio_option *o, const char *text, unsigned int idx)
{
	struct gopt_combo *combo;
	struct value_pair *vp;
	int i, active = 0;

	combo = __gopt_new_combo(o, idx);

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		gtk_combo_box_append_text(GTK_COMBO_BOX(combo->combo), vp->ival);
		if (o->def && !strcmp(vp->ival, o->def))
			active = i;
		if (text && !strcmp(vp->ival, text))
			active = i;
		vp++;
		i++;
	}

	gtk_combo_box_set_active(GTK_COMBO_BOX(combo->combo), active);
	return &combo->gopt;
}

static struct gopt *gopt_new_combo_int(struct fio_option *o, unsigned int *ip, unsigned int idx)
{
	struct gopt_combo *combo;
	struct value_pair *vp;
	int i, active = 0;

	combo = __gopt_new_combo(o, idx);

	i = 0;
	vp = &o->posval[0];
	while (vp->ival) {
		gtk_combo_box_append_text(GTK_COMBO_BOX(combo->combo), vp->ival);
		if (ip && vp->oval == *ip)
			active = i;
		vp++;
		i++;
	}

	gtk_combo_box_set_active(GTK_COMBO_BOX(combo->combo), active);
	return &combo->gopt;
}

static struct gopt *gopt_new_str_multi(struct fio_option *o, unsigned int idx)
{
	struct gopt_str_multi *m;
	struct value_pair *vp;
	GtkWidget *frame, *hbox;
	int i;

	m = malloc(sizeof(*m));
	m->gopt.box = gtk_hbox_new(FALSE, 3);
	gopt_mark_index(&m->gopt, idx);

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
		vp++;
	}

	return &m->gopt;
}

static void gopt_int_changed(GtkSpinButton *spin, gpointer data)
{
	struct gopt_int *i = (struct gopt_int *) data;
	struct fio_option *o = &fio_options[i->gopt.opt_index];

	printf("int %s changed\n", o->name);
}

static struct gopt_int *__gopt_new_int(struct fio_option *o, unsigned long long *p,
				       unsigned int idx)
{
	unsigned long long defval;
	struct gopt_int *i;
	guint maxval, interval;
	GtkWidget *label;

	i = malloc(sizeof(*i));
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

		check_str_bytes(o->def, &val, NULL);
		defval = val;
	}

	interval = 1.0;
	if (o->interval)
		interval = o->interval;

	i->spin = gtk_spin_button_new_with_range(o->minval, maxval, interval);
	gopt_mark_index(&i->gopt, idx);
	gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(i->spin), GTK_UPDATE_IF_VALID);
	gtk_spin_button_set_value(GTK_SPIN_BUTTON(i->spin), defval);
	g_signal_connect(G_OBJECT(i->spin), "value-changed", G_CALLBACK(gopt_int_changed), i);

	gtk_box_pack_start(GTK_BOX(i->gopt.box), i->spin, FALSE, FALSE, 0);
	gtk_box_pack_start(GTK_BOX(i->gopt.box), label, FALSE, FALSE, 0);

	return i;
}

static struct gopt *gopt_new_int(struct fio_option *o, unsigned int *ip, unsigned int idx)
{
	unsigned long long ullp;
	struct gopt_int *i;

	if (ip) {
		ullp = *ip;
		i = __gopt_new_int(o, &ullp, idx);
	} else
		i = __gopt_new_int(o, NULL, idx);

	return &i->gopt;
}

static struct gopt *gopt_new_ullong(struct fio_option *o, unsigned long long *p,
				    unsigned int idx)
{
	struct gopt_int *i;

	i = __gopt_new_int(o, p, idx);
	return &i->gopt;
}

static void gopt_bool_toggled(GtkToggleButton *button, gpointer data)
{
	struct gopt_bool *b = (struct gopt_bool *) data;
	struct fio_option *o = &fio_options[b->gopt.opt_index];
	gboolean set;

	set = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(b->check));
	gopt_set_children_visible(o, set);
}

static struct gopt *gopt_new_bool(struct fio_option *o, unsigned int *val, unsigned int idx)
{
	struct gopt_bool *b;
	GtkWidget *label;
	int defstate = 0;

	b = malloc(sizeof(*b));
	b->gopt.box = gtk_hbox_new(FALSE, 3);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	b->check = gtk_check_button_new();
	gopt_mark_index(&b->gopt, idx);
	if (val)
		defstate = *val;
	else if (o->def && !strcmp(o->def, "1"))
		defstate = 1;

	gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(b->check), defstate);
	g_signal_connect(G_OBJECT(b->check), "toggled", G_CALLBACK(gopt_bool_toggled), b);

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

static struct gopt *gopt_new_int_range(struct fio_option *o, unsigned int **ip,
				       unsigned int idx)
{
	struct gopt_range *r;
	gint maxval, defval;
	GtkWidget *label;
	guint interval;
	int i;

	r = malloc(sizeof(*r));
	r->gopt.box = gtk_hbox_new(FALSE, 3);
	gopt_mark_index(&r->gopt, idx);
	if (!o->lname)
		label = gtk_label_new(o->name);
	else
		label = gtk_label_new(o->lname);

	maxval = o->maxval;
	if (!maxval)
		maxval = INT_MAX;

	defval = 0;
	if (o->def) {
		long long val;

		check_str_bytes(o->def, &val, NULL);
		defval = val;
	}

	interval = 1.0;
	if (o->interval)
		interval = o->interval;

	for (i = 0; i < GOPT_RANGE_SPIN; i++) {
		r->spins[i] = gtk_spin_button_new_with_range(o->minval, maxval, interval);
		gtk_spin_button_set_update_policy(GTK_SPIN_BUTTON(r->spins[i]), GTK_UPDATE_IF_VALID);
		if (ip)
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(r->spins[i]), *ip[i]);
		else
			gtk_spin_button_set_value(GTK_SPIN_BUTTON(r->spins[i]), defval);

		gtk_box_pack_start(GTK_BOX(r->gopt.box), r->spins[i], FALSE, FALSE, 0);
		g_signal_connect(G_OBJECT(r->spins[i]), "value-changed", G_CALLBACK(range_value_changed), r);
	}

	gtk_box_pack_start(GTK_BOX(r->gopt.box), label, FALSE, FALSE, 0);
	return &r->gopt;
}

static void gopt_add_option(GtkWidget *hbox, struct fio_option *o,
			    unsigned int opt_index, struct thread_options *to)
{
	struct gopt *go = NULL;

	switch (o->type) {
	case FIO_OPT_STR_VAL:
	case FIO_OPT_STR_VAL_TIME: {
		unsigned long long *ullp = NULL;

		if (o->off1)
			ullp = td_var(to, o->off1);

		go = gopt_new_ullong(o, ullp, opt_index);
		break;
		}
	case FIO_OPT_INT: {
		unsigned int *ip = NULL;

		if (o->off1)
			ip = td_var(to, o->off1);

		go = gopt_new_int(o, ip, opt_index);
		break;
		}
	case FIO_OPT_STR_SET:
	case FIO_OPT_BOOL: {
		unsigned int *ip = NULL;

		if (o->off1)
			ip = td_var(to, o->off1);

		go = gopt_new_bool(o, ip, opt_index);
		break;
		}
	case FIO_OPT_STR: {
		unsigned int *ip = NULL;

		if (o->off1)
			ip = td_var(to, o->off1);

		go = gopt_new_combo_int(o, ip, opt_index);
		break;
		}
	case FIO_OPT_STR_STORE: {
		char *text = NULL;

		if (o->off1) {
			char **p = td_var(to, o->off1);
			text = *p;
		}

		if (!o->posval[0].ival) {
			go = gopt_new_str_store(o, text, opt_index);
			break;
		}

		go = gopt_new_combo_str(o, text, opt_index);
		break;
		}
	case FIO_OPT_STR_MULTI:
		go = gopt_new_str_multi(o, opt_index);
		break;
	case FIO_OPT_RANGE: {
		unsigned int *ip[4] = { td_var(to, o->off1),
					td_var(to, o->off2),
					td_var(to, o->off3),
					td_var(to, o->off4) };

		go = gopt_new_int_range(o, ip, opt_index);
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

		go->opt_type = o->type;

		dest = gopt_get_group_frame(hbox, o->group);
		if (!dest)
			gtk_box_pack_start(GTK_BOX(hbox), go->box, FALSE, FALSE, 5);
		else
			gtk_box_pack_start(GTK_BOX(dest), go->box, FALSE, FALSE, 5);
	}
}

static void gopt_add_options(GtkWidget **vboxes, struct thread_options *to)
{
	GtkWidget *hbox = NULL;
	int i;

	for (i = 0; fio_options[i].name; i++) {
		struct fio_option *o = &fio_options[i];
		unsigned int mask = o->category;
		struct opt_group *og;

		while ((og = opt_group_from_mask(&mask)) != NULL) {
			GtkWidget *vbox = vboxes[ffz(~og->mask)];

			hbox = gtk_hbox_new(FALSE, 3);
			gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 5);
			gopt_add_option(hbox, o, i, to);
		}
	}
}

static GtkWidget *gopt_add_group_tab(GtkWidget *notebook, struct opt_group *og)
{
	GtkWidget *box, *vbox, *scroll;

	scroll = gtk_scrolled_window_new(NULL, NULL);
	gtk_container_set_border_width(GTK_CONTAINER(scroll), 5);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

	vbox = gtk_vbox_new(FALSE, 3);
	box = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), box, FALSE, FALSE, 5);
	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scroll), vbox);
	gtk_notebook_append_page(GTK_NOTEBOOK(notebook), scroll, gtk_label_new(og->name));

	return vbox;
}

static void gopt_add_group_tabs(GtkWidget *notebook, GtkWidget **vbox)
{
	struct opt_group *og;
	unsigned int i;

	i = 0;
	do {
		unsigned int mask = (1U << i);

		og = opt_group_from_mask(&mask);
		if (!og)
			break;
		vbox[i] = gopt_add_group_tab(notebook, og);
		i++;
	} while (1);
}

void gopt_get_options_window(GtkWidget *window, struct thread_options *o)
{
	GtkWidget *dialog, *notebook;
	GtkWidget *vboxes[__FIO_OPT_C_NR];

	dialog = gtk_dialog_new_with_buttons("Fio options",
			GTK_WINDOW(window), GTK_DIALOG_DESTROY_WITH_PARENT,
			GTK_STOCK_OK, GTK_RESPONSE_ACCEPT,
			GTK_STOCK_CANCEL, GTK_RESPONSE_REJECT, NULL);

	gtk_widget_set_size_request(GTK_WIDGET(dialog), 1024, 768);

	notebook = gtk_notebook_new();
	gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook), 1);
	gtk_notebook_popup_enable(GTK_NOTEBOOK(notebook));
	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), notebook, TRUE, TRUE, 5);

	gopt_add_group_tabs(notebook, vboxes);

	gopt_add_options(vboxes, o);

	gtk_widget_show_all(dialog);

	gtk_dialog_run(GTK_DIALOG(dialog));

	gtk_widget_destroy(dialog);
}
