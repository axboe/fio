/*
 * gfio - gui front end for fio - the flexible io tester
 *
 * Copyright (C) 2012 Stephen M. Cameron <stephenmcameron@gmail.com>
 *
 * The license below covers all files distributed with fio unless otherwise
 * noted in the file itself.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <assert.h>
#include <stdlib.h>

#include <cairo.h>
#include <gtk/gtk.h>

#include "tickmarks.h"
#include "graph.h"
#include "flist.h"
#include "lib/prio_tree.h"
#include "cairo_text_helpers.h"

/*
 * Allowable difference to show tooltip
 */
#define TOOLTIP_DELTA	0.08

struct xyvalue {
	double x, y;
};

enum {
	GV_F_ON_PRIO	= 1,
	GV_F_PRIO_SKIP	= 2,
};

struct graph_value {
	struct flist_head list;
	struct prio_tree_node node;
	struct flist_head alias;
	unsigned int flags;
	char *tooltip;
	void *value;
};

struct graph_label {
	struct flist_head list;
	char *label;
	struct flist_head value_list;
	struct prio_tree_root prio_tree;
	double r, g, b;
	int hide;
	int value_count;
	struct graph *parent;
};

struct tick_value {
	unsigned int offset;
	double value;
};

struct graph {
	char *title;
	char *xtitle;
	char *ytitle;
	unsigned int xdim, ydim;
	double xoffset, yoffset;
	struct flist_head label_list;
	int per_label_limit;
	const char *font;
	graph_axis_unit_change_callback x_axis_unit_change_callback;
	graph_axis_unit_change_callback y_axis_unit_change_callback;
	unsigned int base_offset;
	unsigned int dont_graph_all_zeroes;
	double left_extra;
	double right_extra;
	double top_extra;
	double bottom_extra;

	double xtick_zero;
	double xtick_delta;
	double xtick_zero_val;
	double xtick_one_val;
	double ytick_zero;
	double ytick_delta;
	double ytick_zero_val;
	double ytick_one_val;
};

void graph_set_size(struct graph *g, unsigned int xdim, unsigned int ydim)
{
	g->xdim = xdim;
	g->ydim = ydim;
}

void graph_set_position(struct graph *g, double xoffset, double yoffset)
{
	g->xoffset = xoffset;
	g->yoffset = yoffset;
}

struct graph *graph_new(unsigned int xdim, unsigned int ydim, const char *font)
{
	struct graph *g;

	g = calloc(1, sizeof(*g));
	INIT_FLIST_HEAD(&g->label_list);
	graph_set_size(g, xdim, ydim);
	g->per_label_limit = -1;
	g->font = font;
	if (!g->font)
		g->font = GRAPH_DEFAULT_FONT;
	return g;
}

void graph_set_font(struct graph *g, const char *font)
{
	g->font = font;
}

void graph_x_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f)
{
	g->x_axis_unit_change_callback = f;
}

void graph_y_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f)
{
	g->y_axis_unit_change_callback = f;
}

static int count_labels(struct graph *g)
{
	struct flist_head *entry;
	int count = 0;

	flist_for_each(entry, &g->label_list)
		count++;

	return count;
}

static int count_values(struct graph_label *l)
{
	struct flist_head *entry;
	int count = 0;

	flist_for_each(entry, &l->value_list)
		count++;

	return count;
}

typedef double (*double_comparator)(double a, double b);

static double mindouble(double a, double b)
{
	return a < b ? a : b;
}

static double maxdouble(double a, double b)
{
	return a < b ? b : a;
}

static double find_double_values(struct graph_label *l, double_comparator cmp)
{
	struct flist_head *entry;
	double answer = 0.0, tmp;
	int first = 1;

	if (flist_empty(&l->value_list))
		return 0.0;

	flist_for_each(entry, &l->value_list) {
		struct graph_value *i;

		i = flist_entry(entry, struct graph_value, list);
		tmp = *(double *) i->value;
		if (first) {
			answer = tmp;
			first = 0;
		} else {
			answer = cmp(answer, tmp);
		}
	}
	return answer;
}

static double find_double_data(struct graph *g, double_comparator cmp)
{
	struct flist_head *entry;
	struct graph_label *i;
	int first = 1;
	double answer, tmp;

	if (flist_empty(&g->label_list))
		return 0.0;

	flist_for_each(entry, &g->label_list) {
		i = flist_entry(entry, struct graph_label, list);
		tmp = find_double_values(i, cmp);
		if (first) {
			answer = tmp;
			first = 0;
		} else {
			answer = cmp(tmp, answer);
		}
	}
	return answer;
}

static double find_min_data(struct graph *g)
{
	return find_double_data(g, mindouble);
}

static double find_max_data(struct graph *g)
{
	return find_double_data(g, maxdouble);
}

static void draw_bars(struct graph *bg, cairo_t *cr, struct graph_label *lb,
			double label_offset, double bar_width,
			double mindata, double maxdata)
{
	struct flist_head *entry;
	double x1, y1, x2, y2;
	int bar_num = 0;
	double domain, range, v;

	domain = (maxdata - mindata);
	range = (double) bg->ydim * 0.80; /* FIXME */
	cairo_stroke(cr);
	flist_for_each(entry, &lb->value_list) {
		struct graph_value *i;

		i = flist_entry(entry, struct graph_value, list);

		x1 = label_offset + (double) bar_num * bar_width + (bar_width * 0.05);
		x2 = x1 + bar_width * 0.90;
		y2 = bg->ydim * 0.90;
		v = *(double *) i->value;
		y1 = y2 - (((v - mindata) / domain) * range);
		cairo_move_to(cr, x1, y1);
		cairo_line_to(cr, x1, y2);
		cairo_line_to(cr, x2, y2);
		cairo_line_to(cr, x2, y1);
		cairo_close_path(cr);
		cairo_fill(cr);
		cairo_stroke(cr);
		bar_num++;
	}
}

static void graph_draw_common(struct graph *g, cairo_t *cr, double *x1,
			      double *y1, double *x2, double *y2)
{
	const double shade_col[3][3] = { { 0.55, 0.54, 0.54 },
					 { 0.80, 0.78, 0.78 },
					 { 0.93, 0.91, 0.91 } };
	int i;

	*x1 = 0.10 * g->xdim;
	*x2 = 0.95 * g->xdim;
	*y1 = 0.10 * g->ydim;
	*y2 = 0.90 * g->ydim;

	/*
	 * Add shade
	 */
	cairo_set_line_width(cr, 1.0);
	for (i = 0; i < 3; i++) {
		float offset = i + 1.0;

		cairo_set_source_rgb(cr, shade_col[i][0], shade_col[i][1], shade_col[i][2]);
		cairo_move_to(cr, offset + *x1, *y1 - offset);
		cairo_line_to(cr, *x2 + offset, *y1 - offset);
		cairo_line_to(cr, *x2 + offset, *y2 - offset);
		cairo_stroke(cr);
	}

	cairo_set_source_rgb(cr, 0, 0, 0);
	cairo_set_line_width(cr, 1.2);

	cairo_move_to(cr, *x1, *y1);
	cairo_line_to(cr, *x1, *y2);
	cairo_line_to(cr, *x2, *y2);
	cairo_line_to(cr, *x2, *y1);
	cairo_line_to(cr, *x1, *y1);
	cairo_stroke(cr);

	draw_centered_text(cr, g->font, g->xdim / 2, g->ydim / 20, 20.0, g->title);
	draw_centered_text(cr, g->font, g->xdim / 2, g->ydim * 0.97, 14.0, g->xtitle);
	draw_vertical_centered_text(cr, g->font, g->xdim * 0.02, g->ydim / 2, 14.0, g->ytitle);
	cairo_stroke(cr);
}

static void graph_draw_x_ticks(struct graph *g, cairo_t *cr,
	double x1, double y1, double x2, double y2,
	double minx, double maxx, int nticks, int add_tm_text)
{
	struct tickmark *tm;
	double tx;
	int i, power_of_ten;
	static double dash[] = { 1.0, 2.0 };

	nticks = calc_tickmarks(minx, maxx, nticks, &tm, &power_of_ten,
		g->x_axis_unit_change_callback == NULL, g->base_offset);
	if (g->x_axis_unit_change_callback)
		g->x_axis_unit_change_callback(g, power_of_ten);

	for (i = 0; i < nticks; i++) {
		tx = (((tm[i].value) - minx) / (maxx - minx)) * (x2 - x1) + x1;

		/*
		 * Update tick delta
		 */
		if (!i) {
			g->xtick_zero = tx;
			g->xtick_zero_val = tm[0].value;
		} else if (i == 1) {
			g->xtick_delta = (tm[1].value - tm[0].value) / (tx - g->xtick_zero);
			g->xtick_one_val = tm[1].value;
		}

		/* really tx < yx || tx > x2, but protect against rounding */
		if (x1 - tx > 0.01 || tx - x2 > 0.01)
			continue;

		/* Draw tick mark */
		cairo_set_line_width(cr, 1.0);
		cairo_move_to(cr, tx, y2);
		cairo_line_to(cr, tx, y2 + (y2 - y1) * 0.03);
		cairo_stroke(cr);

		/* draw grid lines */
		cairo_save(cr);
		cairo_set_dash(cr, dash, 2, 0.66);
		cairo_set_line_width(cr, 0.33);
		cairo_move_to(cr, tx, y1);
		cairo_line_to(cr, tx, y2);
		cairo_stroke(cr);
		cairo_restore(cr);

		if (!add_tm_text)
			continue;

		/* draw tickmark label */
		draw_centered_text(cr, g->font, tx, y2 * 1.04, 12.0, tm[i].string);
		cairo_stroke(cr);
	}
}

static double graph_draw_y_ticks(struct graph *g, cairo_t *cr,
	double x1, double y1, double x2, double y2,
	double miny, double maxy, int nticks, int add_tm_text)
{
	struct tickmark *tm;
	double ty;
	int i, power_of_ten;
	static double dash[] = { 1.0, 2.0 };

	nticks = calc_tickmarks(miny, maxy, nticks, &tm, &power_of_ten,
		g->y_axis_unit_change_callback == NULL, g->base_offset);
	if (g->y_axis_unit_change_callback)
		g->y_axis_unit_change_callback(g, power_of_ten);

	/*
	 * Use highest tickmark as top of graph, not highest value. Otherwise
	 * it's impossible to see what the max value is, if the graph is
	 * fairly flat.
	 */
	maxy = tm[nticks - 1].value;

	for (i = 0; i < nticks; i++) {
		ty = y2 - (((tm[i].value) - miny) / (maxy - miny)) * (y2 - y1);

		/*
		 * Update tick delta
		 */
		if (!i) {
			g->ytick_zero = ty;
			g->ytick_zero_val = tm[0].value;
		} else if (i == 1) {
			g->ytick_delta = (tm[1].value - tm[0].value) / (ty - g->ytick_zero);
			g->ytick_one_val = tm[1].value;
		}

		/* really ty < y1 || ty > y2, but protect against rounding */
		if (y1 - ty > 0.01 || ty - y2 > 0.01)
			continue;

		/* draw tick mark */
		cairo_move_to(cr, x1, ty);
		cairo_line_to(cr, x1 - (x2 - x1) * 0.02, ty);
		cairo_stroke(cr);

		/* draw grid lines */
		cairo_save(cr);
		cairo_set_dash(cr, dash, 2, 0.66);
		cairo_set_line_width(cr, 0.33);
		cairo_move_to(cr, x1, ty);
		cairo_line_to(cr, x2, ty);
		cairo_stroke(cr);
		cairo_restore(cr);

		if (!add_tm_text)
			continue;

		/* draw tickmark label */
		draw_right_justified_text(cr, g->font, x1 - (x2 - x1) * 0.025, ty, 12.0, tm[i].string);
		cairo_stroke(cr);
	}

	/*
	 * Return new max to use
	 */
	return maxy;
}

void bar_graph_draw(struct graph *bg, cairo_t *cr)
{
	double x1, y1, x2, y2;
	double space_per_label, bar_width;
	double label_offset, mindata, maxdata;
	int i, nlabels;
	struct graph_label *lb;
	struct flist_head *entry;

	cairo_save(cr);
	cairo_translate(cr, bg->xoffset, bg->yoffset);
	graph_draw_common(bg, cr, &x1, &y1, &x2, &y2);

	nlabels = count_labels(bg);
	space_per_label = (x2 - x1) / (double) nlabels;

	/*
	 * Start bars at 0 unless we have negative values, otherwise we
	 * present a skewed picture comparing label X and X+1.
	 */
	mindata = find_min_data(bg);
	if (mindata > 0)
		mindata = 0;

	maxdata = find_max_data(bg);

	if (fabs(maxdata - mindata) < 1e-20) {
		draw_centered_text(cr, bg->font,
			x1 + (x2 - x1) / 2.0,
			y1 + (y2 - y1) / 2.0, 20.0, "No good data");
		return;
	}

	maxdata = graph_draw_y_ticks(bg, cr, x1, y1, x2, y2, mindata, maxdata, 10, 1);
	i = 0;
	flist_for_each(entry, &bg->label_list) {
		int nvalues;

		lb = flist_entry(entry, struct graph_label, list);
		nvalues = count_values(lb);
		bar_width = (space_per_label - space_per_label * 0.2) / (double) nvalues;
		label_offset = bg->xdim * 0.1 + space_per_label * (double) i + space_per_label * 0.1;
		draw_bars(bg, cr, lb, label_offset, bar_width, mindata, maxdata);
		// draw_centered_text(cr, label_offset + (bar_width / 2.0 + bar_width * 0.1), bg->ydim * 0.93,
		draw_centered_text(cr, bg->font, x1 + space_per_label * (i + 0.5), bg->ydim * 0.93,
			12.0, lb->label);
		i++;
	}
	cairo_stroke(cr);
	cairo_restore(cr);
}

typedef double (*xy_value_extractor)(struct graph_value *v);

static double getx(struct graph_value *v)
{
	struct xyvalue *xy = v->value;
	return xy->x;
}

static double gety(struct graph_value *v)
{
	struct xyvalue *xy = v->value;
	return xy->y;
}

static double find_xy_value(struct graph *g, xy_value_extractor getvalue, double_comparator cmp)
{
	double tmp, answer = 0.0;
	struct graph_label *i;
	struct graph_value *j;
	struct flist_head *jentry, *entry;
	int first = 1;

	flist_for_each(entry, &g->label_list) {
		i = flist_entry(entry, struct graph_label, list);

		flist_for_each(jentry, &i->value_list) {
			j = flist_entry(jentry, struct graph_value, list);
			tmp = getvalue(j);
			if (first) {
				first = 0;
				answer = tmp;
			}
			answer = cmp(tmp, answer);
		}
	}

	return answer;
}

void line_graph_draw(struct graph *g, cairo_t *cr)
{
	double x1, y1, x2, y2;
	double minx, miny, maxx, maxy, gminx, gminy, gmaxx, gmaxy;
	double tx, ty, top_extra, bottom_extra, left_extra, right_extra;
	struct graph_label *i;
	struct graph_value *j;
	int good_data = 1, first = 1;
	struct flist_head *entry, *lentry;

	cairo_save(cr);
	cairo_translate(cr, g->xoffset, g->yoffset);
	graph_draw_common(g, cr, &x1, &y1, &x2, &y2);

	minx = find_xy_value(g, getx, mindouble);
	maxx = find_xy_value(g, getx, maxdouble);
	miny = find_xy_value(g, gety, mindouble);

	/*
	 * Start graphs at zero, unless we have a value below. Otherwise
	 * it's hard to visually compare the read and write graph, since
	 * the lowest valued one will be the floor of the graph view.
	 */
	if (miny > 0)
		miny = 0;

	maxy = find_xy_value(g, gety, maxdouble);

	if (fabs(maxx - minx) < 1e-20 || fabs(maxy - miny) < 1e-20) {
		good_data = 0;
		minx = 0.0;
		miny = 0.0;
		maxx = 10.0;
		maxy = 100.0;
	}

	top_extra = 0.0;
	bottom_extra = 0.0;
	left_extra = 0.0;
	right_extra = 0.0;

	if (g->top_extra > 0.001)
		top_extra = fabs(maxy - miny) * g->top_extra;
	if (g->bottom_extra > 0.001)
		bottom_extra = fabs(maxy - miny) * g->bottom_extra;
	if (g->left_extra > 0.001)
		left_extra = fabs(maxx - minx) * g->left_extra;
	if (g->right_extra > 0.001)
		right_extra = fabs(maxx - minx) * g->right_extra;

	gminx = minx - left_extra;
	gmaxx = maxx + right_extra;
	gminy = miny - bottom_extra;
	gmaxy = maxy + top_extra;

	graph_draw_x_ticks(g, cr, x1, y1, x2, y2, gminx, gmaxx, 10, good_data);
	gmaxy = graph_draw_y_ticks(g, cr, x1, y1, x2, y2, gminy, gmaxy, 10, good_data);

	if (!good_data)
		goto skip_data;

	cairo_set_line_width(cr, 1.5);
	cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);

	flist_for_each(lentry, &g->label_list) {
		i = flist_entry(lentry, struct graph_label, list);
		first = 1;
		if (i->hide || i->r < 0) /* invisible data */
			continue;

		cairo_set_source_rgb(cr, i->r, i->g, i->b);
		flist_for_each(entry, &i->value_list) {
			j = flist_entry(entry, struct graph_value, list);
			tx = ((getx(j) - gminx) / (gmaxx - gminx)) * (x2 - x1) + x1;
			ty = y2 - ((gety(j) - gminy) / (gmaxy - gminy)) * (y2 - y1);
			if (first) {
				cairo_move_to(cr, tx, ty);
				first = 0;
			} else
				cairo_line_to(cr, tx, ty);
		}
		cairo_stroke(cr);
	}

skip_data:
	cairo_restore(cr);
}

static void setstring(char **str, const char *value)
{
	free(*str);
	*str = strdup(value);
}

void graph_title(struct graph *bg, const char *title)
{
	setstring(&bg->title, title);
}

void graph_x_title(struct graph *bg, const char *title)
{
	setstring(&bg->xtitle, title);
}

void graph_y_title(struct graph *bg, const char *title)
{
	setstring(&bg->ytitle, title);
}

static struct graph_label *graph_find_label(struct graph *bg,
				const char *label)
{
	struct flist_head *entry;
	struct graph_label *i;

	flist_for_each(entry, &bg->label_list) {
		i = flist_entry(entry, struct graph_label, list);

		if (strcmp(label, i->label) == 0)
			return i;
	}

	return NULL;
}

graph_label_t graph_add_label(struct graph *bg, const char *label)
{
	struct graph_label *i;

	i = graph_find_label(bg, label);
	if (i)
		return i; /* already present. */
	i = calloc(1, sizeof(*i));
	INIT_FLIST_HEAD(&i->value_list);
	i->parent = bg;
	setstring(&i->label, label);
	flist_add_tail(&i->list, &bg->label_list);
	INIT_PRIO_TREE_ROOT(&i->prio_tree);
	return i;
}

static void __graph_value_drop(struct graph_label *l, struct graph_value *v)
{
	flist_del_init(&v->list);
	if (v->tooltip)
		free(v->tooltip);
	free(v->value);
	free(v);
	l->value_count--;
}

static void graph_value_drop(struct graph_label *l, struct graph_value *v)
{
	if (v->flags & GV_F_PRIO_SKIP) {
		__graph_value_drop(l, v);
		return;
	}

	/*
	 * Find head, the guy that's on the prio tree
	 */
	while (!(v->flags & GV_F_ON_PRIO)) {
		assert(!flist_empty(&v->alias));
		v = flist_first_entry(&v->alias, struct graph_value, alias);
	}

	prio_tree_remove(&l->prio_tree, &v->node);

	/*
	 * Free aliases
	 */
	while (!flist_empty(&v->alias)) {
		struct graph_value *a;

		a = flist_first_entry(&v->alias, struct graph_value, alias);
		flist_del_init(&a->alias);

		__graph_value_drop(l, a);
	}

	__graph_value_drop(l, v);
}

static void graph_label_add_value(struct graph_label *i, void *value,
				  const char *tooltip)
{
	struct graph *g = i->parent;
	struct graph_value *x;

	x = malloc(sizeof(*x));
	memset(x, 0, sizeof(*x));
	INIT_FLIST_HEAD(&x->alias);
	INIT_FLIST_HEAD(&x->list);
	flist_add_tail(&x->list, &i->value_list);
	i->value_count++;
	x->value = value;

	if (tooltip) {
		double xval = getx(x);
		double minx = xval - (g->xtick_one_val * TOOLTIP_DELTA);
		double maxx = xval + (g->xtick_one_val * TOOLTIP_DELTA);
		struct prio_tree_node *ret;

		/*
		 * use msec to avoid dropping too much precision when
		 * storing as an integer.
		 */
		minx = minx * 1000.0;
		maxx = maxx * 1000.0;

		INIT_PRIO_TREE_NODE(&x->node);
		x->node.start = minx;
		x->node.last = maxx;
		x->tooltip = strdup(tooltip);
		if (x->node.last == x->node.start) {
			x->node.last += fabs(g->xtick_delta);
			if (x->node.last == x->node.start)
				x->node.last++;
		}

		/*
		 * If ret != &x->node, we have an alias. Since the values
		 * should be identical, we can drop it
		 */
		ret = prio_tree_insert(&i->prio_tree, &x->node);
		if (ret != &x->node) {
			struct graph_value *alias;

			alias = container_of(ret, struct graph_value, node);
			flist_add_tail(&x->alias, &alias->alias);
		} else
			x->flags = GV_F_ON_PRIO;
	} else
		x->flags = GV_F_PRIO_SKIP;

	if (g->per_label_limit != -1 &&
		i->value_count > g->per_label_limit) {
		int to_drop = 1;

		/*
		 * If the limit was dynamically reduced, making us more
		 * than 1 entry ahead after adding this one, drop two
		 * entries. This will make us (eventually) reach the
		 * specified limit.
		 */
		if (i->value_count - g->per_label_limit >= 2)
			to_drop = 2;

		while (to_drop-- && !flist_empty(&i->value_list)) {
			x = flist_first_entry(&i->value_list, struct graph_value, list);
			graph_value_drop(i, x);

			/*
			 * If we have aliases, we could drop > 1 above.
			 */
			if (i->value_count <= g->per_label_limit)
				break;
		}
	}
}

int graph_add_data(struct graph *bg, graph_label_t label, const double value)
{
	struct graph_label *i = label;
	double *d;

	d = malloc(sizeof(*d));
	*d = value;

	graph_label_add_value(i, d, NULL);
	return 0;
}

static int graph_nonzero_y(struct graph_label *l)
{
	struct flist_head *entry;

	flist_for_each(entry, &l->value_list) {
		struct graph_value *v;

		v = flist_entry(entry, struct graph_value, list);
		if (gety(v) != 0.0)
			return 1;
	}

	return 0;
}

int graph_add_xy_data(struct graph *bg, graph_label_t label,
		      const double x, const double y, const char *tooltip)
{
	struct graph_label *i = label;
	struct xyvalue *xy;

	if (bg->dont_graph_all_zeroes && y == 0.0 && !graph_nonzero_y(i))
		i->hide = 1;
	else
		i->hide = 0;

	xy = malloc(sizeof(*xy));
	xy->x = x;
	xy->y = y;

	graph_label_add_value(i, xy, tooltip);
	return 0;
}

static void graph_free_values(struct graph_label *l)
{
	struct graph_value *i;

	while (!flist_empty(&l->value_list)) {
		i = flist_first_entry(&l->value_list, struct graph_value, list);
		graph_value_drop(l, i);
	}
}

static void graph_free_labels(struct graph *g)
{
	struct graph_label *i;

	while (!flist_empty(&g->label_list)) {
		i = flist_first_entry(&g->label_list, struct graph_label, list);
		flist_del(&i->list);
		graph_free_values(i);
		free(i);
	}
}

void graph_clear_values(struct graph *g)
{
	struct flist_head *node;
	struct graph_label *i;

	flist_for_each(node, &g->label_list) {
		i = flist_entry(node, struct graph_label, list);
		graph_free_values(i);
	}
}

void graph_set_color(struct graph *gr, graph_label_t label, double red,
		     double green, double blue)
{
	struct graph_label *i = label;
	double r, g, b;

	if (red < 0.0) { /* invisible color */
		r = -1.0;
		g = -1.0;
		b = -1.0;
	} else {
		r = fabs(red);
		g = fabs(green);
		b = fabs(blue);

		if (r > 1.0)
			r = 1.0;
		if (g > 1.0)
			g = 1.0;
		if (b > 1.0)
			b = 1.0;
	}

	i->r = r;
	i->g = g;
	i->b = b;
}

void graph_free(struct graph *bg)
{
	free(bg->title);
	free(bg->xtitle);
	free(bg->ytitle);
	graph_free_labels(bg);
}

/* For each line in the line graph, up to per_label_limit segments may
 * be added.  After that, adding more data to the end of the line
 * causes data to drop off of the front of the line.
 */
void line_graph_set_data_count_limit(struct graph *g, int per_label_limit)
{
	g->per_label_limit = per_label_limit;
}

void graph_add_extra_space(struct graph *g, double left_percent,
			   double right_percent, double top_percent,
			   double bottom_percent)
{
	g->left_extra = left_percent;
	g->right_extra = right_percent;
	g->top_extra = top_percent;
	g->bottom_extra = bottom_percent;
}

/*
 * Normally values are logged in a base unit of 0, but for other purposes
 * it makes more sense to log in higher unit. For instance for bandwidth
 * purposes, you may want to log in KB/sec (or MB/sec) rather than bytes/sec.
 */
void graph_set_base_offset(struct graph *g, unsigned int base_offset)
{
	g->base_offset = base_offset;
}

int graph_has_tooltips(struct graph *g)
{
	struct flist_head *entry;
	struct graph_label *i;

	flist_for_each(entry, &g->label_list) {
		i = flist_entry(entry, struct graph_label, list);

		if (!prio_tree_empty(&i->prio_tree))
			return 1;
	}

	return 0;
}

int graph_contains_xy(struct graph *g, int x, int y)
{
	int first_x = g->xoffset;
	int last_x = g->xoffset + g->xdim;
	int first_y = g->yoffset;
	int last_y = g->yoffset + g->ydim;

	return (x >= first_x && x <= last_x) && (y >= first_y && y <= last_y);
}

const char *graph_find_tooltip(struct graph *g, int ix, int iy)
{
	double x = ix, y = iy;
	struct prio_tree_iter iter;
	struct prio_tree_node *n;
	struct graph_value *best = NULL;
	struct flist_head *entry;
	double best_delta;
	double maxy, miny;

	x -= g->xoffset;
	y -= g->yoffset;

	x = g->xtick_zero_val + ((x - g->xtick_zero) * g->xtick_delta);
	y = g->ytick_zero_val + ((y - g->ytick_zero) * g->ytick_delta);

	x = x * 1000.0;
	maxy = y + (g->ytick_one_val * TOOLTIP_DELTA);
	miny = y - (g->ytick_one_val * TOOLTIP_DELTA);
	best_delta = UINT_MAX;
	flist_for_each(entry, &g->label_list) {
		struct graph_label *i;

		i = flist_entry(entry, struct graph_label, list);
		if (i->hide)
			continue;

		INIT_PRIO_TREE_ITER(&iter);
		prio_tree_iter_init(&iter, &i->prio_tree, x, x);

		n = prio_tree_next(&iter);
		if (!n)
			continue;

		do {
			struct graph_value *v, *rootv;
			double yval, ydiff;

			v = container_of(n, struct graph_value, node);
			rootv = v;
			do {
				yval = gety(v);
				ydiff = fabs(yval - y);

				/*
				 * zero delta, or within or match critera, break
				 */
				if (ydiff < best_delta) {
					best_delta = ydiff;
					if (!best_delta ||
					    (yval >= miny && yval <= maxy)) {
						best = v;
						break;
					}
				}
				if (!flist_empty(&v->alias))
					v = flist_first_entry(&v->alias, struct graph_value, alias);
			} while (v != rootv);
		} while ((n = prio_tree_next(&iter)) != NULL);

		/*
		 * If we got matches in one label, don't check others.
		 */
		if (best)
			break;
	}

	if (best)
		return best->tooltip;

	return NULL;
}

void graph_set_graph_all_zeroes(struct graph *g, unsigned int set)
{
	g->dont_graph_all_zeroes = !set;
}
