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

#include <cairo.h>
#include <gtk/gtk.h>

#include "tickmarks.h"

struct xyvalue {
	double x, y;
};

struct graph_value {
	struct graph_value *next;
	void *value;
};

struct graph_label {
	char *label;
	struct graph_value *tail;
	struct graph_value *values;
	struct graph_label *next;
	double r, g, b;
	int value_count;
	struct graph *parent;
};

struct graph {
	char *title;
	char *xtitle;
	char *ytitle;
	unsigned int xdim, ydim;
	struct graph_label *labels;
	struct graph_label *tail;
	int per_label_limit;
	const char *font;
};

void graph_set_size(struct graph *g, unsigned int xdim, unsigned int ydim)
{
	g->xdim = xdim;
	g->ydim = ydim;
}

struct graph *graph_new(unsigned int xdim, unsigned int ydim, const char *font)
{
	struct graph *g;

	g = calloc(1, sizeof(*g));
	graph_set_size(g, xdim, ydim);
	g->per_label_limit = -1;
	g->font = font;
	if (!g->font)
		g->font = "Sans";
	return g;
}

static int count_labels(struct graph_label *labels)
{
	int count = 0;
	struct graph_label *i;

	for (i = labels; i; i = i->next)
		count++;
	return count;
}

static int count_values(struct graph_value *values)
{
	int count = 0;
	struct graph_value *i;

	for (i = values; i; i = i->next)
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

static double find_double_values(struct graph_value *values, double_comparator cmp)
{
	struct graph_value *i;
	int first = 1;
	double answer, tmp;

	assert(values != NULL);
	answer = 0.0; /* shut the compiler up, might need to think harder though. */
	for (i = values; i; i = i->next) {
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

static double find_double_data(struct graph_label *labels, double_comparator cmp)
{
	struct graph_label *i;
	int first = 1;
	double answer, tmp;

	assert(labels != NULL);
	answer = 0.0; /* shut the compiler up, might need to think harder though. */
	for (i = labels; i; i = i->next) {
		tmp = find_double_values(i->values, cmp);
		if (first) {
			answer = tmp;
			first = 0;
		} else {
			answer = cmp(tmp, answer);
		}
	}
	return answer;
}

static double find_min_data(struct graph_label *labels)
{
	return find_double_data(labels, mindouble);
}

static double find_max_data(struct graph_label *labels)
{
	return find_double_data(labels, maxdouble);
}

static void draw_bars(struct graph *bg, cairo_t *cr, struct graph_label *lb,
			double label_offset, double bar_width,
			double mindata, double maxdata)
{
	struct graph_value *i;
	double x1, y1, x2, y2;
	int bar_num = 0;
	double domain, range, v;

	domain = (maxdata - mindata);
	range = (double) bg->ydim * 0.80; /* FIXME */
	cairo_stroke(cr);
	for (i = lb->values; i; i = i->next) {

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

static void draw_aligned_text(struct graph *g, cairo_t *cr, double x, double y,
			       double fontsize, const char *text, int alignment)
{
#define CENTERED 0
#define LEFT_JUSTIFIED 1
#define RIGHT_JUSTIFIED 2

	double factor, direction;
	cairo_text_extents_t extents;

	switch(alignment) {
		case CENTERED:
			direction = -1.0;
			factor = 0.5;
			break;
		case RIGHT_JUSTIFIED:
			direction = -1.0;
			factor = 1.0;
			break;
		case LEFT_JUSTIFIED:
		default:
			direction = 1.0;
			factor = 1.0;
			break;
	}
	cairo_select_font_face (cr, g->font, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);

	cairo_set_font_size(cr, fontsize);
	cairo_text_extents(cr, text, &extents);
	x = x + direction * (factor * extents.width  + extents.x_bearing);
	y = y - (extents.height / 2 + extents.y_bearing);

	cairo_move_to(cr, x, y);
	cairo_show_text(cr, text);
}

static inline void draw_centered_text(struct graph *g, cairo_t *cr, double x, double y,
			       double fontsize, const char *text)
{
	draw_aligned_text(g, cr, x, y, fontsize, text, CENTERED);
}

static inline void draw_right_justified_text(struct graph *g, cairo_t *cr,
				double x, double y,
				double fontsize, const char *text)
{
	draw_aligned_text(g, cr, x, y, fontsize, text, RIGHT_JUSTIFIED);
}

static inline void draw_left_justified_text(struct graph *g, cairo_t *cr,
				double x, double y,
				double fontsize, const char *text)
{
	draw_aligned_text(g, cr, x, y, fontsize, text, LEFT_JUSTIFIED);
}

static void draw_vertical_centered_text(struct graph *g, cairo_t *cr, double x,
					double y, double fontsize,
					const char *text)
{
	double sx, sy;
	cairo_text_extents_t extents;

	cairo_select_font_face(cr, g->font, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);

	cairo_set_font_size(cr, fontsize);
	cairo_text_extents(cr, text, &extents);
	sx = x;
	sy = y;
	y = y + (extents.width / 2.0 + extents.x_bearing);
	x = x - (extents.height / 2.0 + extents.y_bearing);

	cairo_move_to(cr, x, y);
	cairo_save(cr);
	cairo_translate(cr, -sx, -sy);
	cairo_rotate(cr, -90.0 * M_PI / 180.0);
	cairo_translate(cr, sx, sy);
	cairo_show_text(cr, text);
	cairo_restore(cr);
}

static void graph_draw_common(struct graph *g, cairo_t *cr,
	double *x1, double *y1, double *x2, double *y2)
{
        cairo_set_source_rgb(cr, 0, 0, 0);
        cairo_set_line_width (cr, 0.8);

	*x1 = 0.15 * g->xdim;	
	*x2 = 0.95 * g->xdim;
	*y1 = 0.10 * g->ydim;	
	*y2 = 0.90 * g->ydim;

	cairo_move_to(cr, *x1, *y1);
	cairo_line_to(cr, *x1, *y2);
	cairo_line_to(cr, *x2, *y2);
	cairo_line_to(cr, *x2, *y1);
	cairo_line_to(cr, *x1, *y1);
	cairo_stroke(cr);

	draw_centered_text(g, cr, g->xdim / 2, g->ydim / 20, 20.0, g->title);
	draw_centered_text(g, cr, g->xdim / 2, g->ydim * 0.97, 14.0, g->xtitle);
	draw_vertical_centered_text(g, cr, g->xdim * 0.02, g->ydim / 2, 14.0, g->ytitle);
	cairo_stroke(cr);
}

static void graph_draw_x_ticks(struct graph *g, cairo_t *cr,
	double x1, double y1, double x2, double y2,
	double minx, double maxx, int nticks)
{
	struct tickmark *tm;
	double tx;
	int i;
	static double dash[] = { 1.0, 2.0 };

	nticks = calc_tickmarks(minx, maxx, nticks, &tm);

	for (i = 0; i < nticks; i++) {
		tx = (((tm[i].value) - minx) / (maxx - minx)) * (x2 - x1) + x1;
		if (tx < x1 || tx > x2)
			continue;

		/* Draw tick mark */
		cairo_set_line_width(cr, 0.8);
		cairo_move_to(cr, tx, y2);
		cairo_line_to(cr, tx, y2 + (y2 - y1) * 0.03);
		cairo_stroke(cr);

		/* draw grid lines */
		cairo_save(cr);
		cairo_set_dash(cr, dash, 2, 2.0);
		cairo_set_line_width(cr, 0.5);
		cairo_move_to(cr, tx, y1);
		cairo_line_to(cr, tx, y2);
		cairo_stroke(cr);
		cairo_restore(cr);

		/* draw tickmark label */
		draw_centered_text(g, cr, tx, y2 * 1.04, 12.0, tm[i].string);
		cairo_stroke(cr);
		
	}
}

static void graph_draw_y_ticks(struct graph *g, cairo_t *cr,
	double x1, double y1, double x2, double y2,
	double miny, double maxy, int nticks)
{
	struct tickmark *tm;
	double ty;
	int i;
	static double dash[] = { 2.0, 2.0 };

	nticks = calc_tickmarks(miny, maxy, nticks, &tm);

	for (i = 0; i < nticks; i++) {
		ty = y2 - (((tm[i].value) - miny) / (maxy - miny)) * (y2 - y1);
		if (ty < y1 || ty > y2)
			continue;
		/* draw tick mark */
		cairo_move_to(cr, x1, ty);
		cairo_line_to(cr, x1 - (x2 - x1) * 0.02, ty);
		cairo_stroke(cr);

		/* draw grid lines */
		cairo_save(cr);
		cairo_set_dash(cr, dash, 2, 2.0);
		cairo_set_line_width(cr, 0.5);
		cairo_move_to(cr, x1, ty);
		cairo_line_to(cr, x2, ty);
		cairo_stroke(cr);
		cairo_restore(cr);

		/* draw tickmark label */
		draw_right_justified_text(g, cr, x1 - (x2 - x1) * 0.025, ty, 12.0, tm[i].string);
		cairo_stroke(cr);
	}
}

void bar_graph_draw(struct graph *bg, cairo_t *cr)
{
	double x1, y1, x2, y2;
	double space_per_label, bar_width;
	double label_offset, mindata, maxdata;
	int i, nlabels;
	struct graph_label *lb;

	cairo_save(cr);
	graph_draw_common(bg, cr, &x1, &y1, &x2, &y2);

	nlabels = count_labels(bg->labels);
	space_per_label = (x2 - x1) / (double) nlabels; 

	mindata = find_min_data(bg->labels);
	maxdata = find_max_data(bg->labels);

	if (fabs(maxdata - mindata) < 1e-20) {
		draw_centered_text(bg, cr,
			x1 + (x2 - x1) / 2.0,
			y1 + (y2 - y1) / 2.0, 20.0, "No good data");
		return;
	}

	graph_draw_y_ticks(bg, cr, x1, y1, x2, y2, mindata, maxdata, 10);

	i = 0;
	for (lb = bg->labels; lb; lb = lb->next) {
		int nvalues;
		nvalues = count_values(lb->values);
		bar_width = (space_per_label - space_per_label * 0.2) / (double) nvalues;
		label_offset = bg->xdim * 0.1 + space_per_label * (double) i + space_per_label * 0.1;
		draw_bars(bg, cr, lb, label_offset, bar_width, mindata, maxdata);
		// draw_centered_text(cr, label_offset + (bar_width / 2.0 + bar_width * 0.1), bg->ydim * 0.93,
		draw_centered_text(bg, cr, x1 + space_per_label * (i + 0.5), bg->ydim * 0.93,
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
	int first = 1;

	for (i = g->labels; i; i = i->next)
		for (j = i->values; j; j = j->next) {
			tmp = getvalue(j);
			if (first) {
				first = 0;
				answer = tmp;
			}
			answer = cmp(tmp, answer);	
		}
	return answer;
} 

void line_graph_draw(struct graph *g, cairo_t *cr)
{
	double x1, y1, x2, y2;
	double minx, miny, maxx, maxy;
	double tx, ty;
	struct graph_label *i;
	struct graph_value *j;
	int good_data = 1, first = 1;

	cairo_save(cr);
	graph_draw_common(g, cr, &x1, &y1, &x2, &y2);

	minx = find_xy_value(g, getx, mindouble);
	maxx = find_xy_value(g, getx, maxdouble);
	miny = find_xy_value(g, gety, mindouble);
	maxy = find_xy_value(g, gety, maxdouble);

	if (fabs(maxx - minx) < 1e-20 || fabs(maxy - miny) < 1e-20) {
		good_data = 0;
		minx = 0.0;
		miny = 0.0;
		maxx = 10.0;
		maxy = 100.0;
	}

	graph_draw_x_ticks(g, cr, x1, y1, x2, y2, minx, maxx, 10);
	graph_draw_y_ticks(g, cr, x1, y1, x2, y2, miny, maxy, 10);

	if (!good_data)
		goto skip_data;

	cairo_set_line_width(cr, 1.5);
	for (i = g->labels; i; i = i->next) {
		first = 1;
		if (i->r < 0) /* invisible data */
			continue;
		cairo_set_source_rgb(cr, i->r, i->g, i->b);
		for (j = i->values; j; j = j->next) {
			tx = ((getx(j) - minx) / (maxx - minx)) * (x2 - x1) + x1;
			ty = y2 - ((gety(j) - miny) / (maxy - miny)) * (y2 - y1);
			if (first) {
				cairo_move_to(cr, tx, ty);
				first = 0;
			} else {
				cairo_line_to(cr, tx, ty);
			}
		}
		cairo_stroke(cr);
	}

skip_data:
	cairo_restore(cr);

}

static void gfree(void *f)
{
	if (f)
		free(f);
}

static void setstring(char **str, const char *value)
{
	gfree(*str);
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
	struct graph_label *i;
	
	for (i = bg->labels; i; i = i->next)
		if (strcmp(label, i->label) == 0)
			return i;
	return NULL;
}

void graph_add_label(struct graph *bg, const char *label)
{
	struct graph_label *i;
	
	i = graph_find_label(bg, label);
	if (i)
		return; /* already present. */
	i = calloc(1, sizeof(*i));
	i->parent = bg;
	setstring(&i->label, label);
	i->next = NULL;
	if (!bg->tail)
		bg->labels = i;
	else
		bg->tail->next = i;
	bg->tail = i;
}

static void graph_label_add_value(struct graph_label *i, void *value)
{
	struct graph_value *x;

	x = malloc(sizeof(*x));
	x->value = value;
	x->next = NULL;
	if (!i->tail) {
		i->values = x;
	} else {
		i->tail->next = x;
	}
	i->tail = x;
	i->value_count++;

	if (i->parent->per_label_limit != -1 &&
		i->value_count > i->parent->per_label_limit) {
		x = i->values;
		i->values = i->values->next;
		free(x->value);
		free(x);
		i->value_count--;
	}
}

int graph_add_data(struct graph *bg, const char *label, const double value)
{
	struct graph_label *i;
	double *d;

	d = malloc(sizeof(*d));
	*d = value;

	i = graph_find_label(bg, label);
	if (!i)
		return -1;
	graph_label_add_value(i, d);
	return 0;
}

int graph_add_xy_data(struct graph *bg, const char *label,
		const double x, const double y)
{
	struct graph_label *i;
	struct xyvalue *xy;

	xy = malloc(sizeof(*xy));
	xy->x = x;
	xy->y = y;

	i = graph_find_label(bg, label);
	if (!i)
		return -1;
	graph_label_add_value(i, xy);
	return 0;
}

static void graph_free_values(struct graph_value *values)
{
	struct graph_value *i, *next;

	for (i = values; i; i = next) {
		next = i->next;
		gfree(i->value);
		gfree(i);
	}	
}

static void graph_free_labels(struct graph_label *labels)
{
	struct graph_label *i, *next;

	for (i = labels; i; i = next) {
		next = i->next;
		graph_free_values(i->values);
		gfree(i);
	}	
}

void graph_set_color(struct graph *gr, const char *label,
	double red, double green, double blue)
{
	struct graph_label *i;
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
			b =1.0;
	}

	for (i = gr->labels; i; i = i->next)
		if (strcmp(i->label, label) == 0) {
			i->r = r;	
			i->g = g;	
			i->b = b;	
			break;
		}
}

void graph_free(struct graph *bg)
{
	gfree(bg->title);
	gfree(bg->xtitle);
	gfree(bg->ytitle);
	graph_free_labels(bg->labels);
}

/* For each line in the line graph, up to per_label_limit segments may
 * be added.  After that, adding more data to the end of the line
 * causes data to drop off of the front of the line.
 */
void line_graph_set_data_count_limit(struct graph *g, int per_label_limit)
{
	g->per_label_limit = per_label_limit;
}

