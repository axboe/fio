#ifndef GRAPH_H
#define GRAPH_H

struct graph;

struct graph *graph_new(int xdim, int ydim);
void bar_graph_draw(struct graph *g, cairo_t *cr);
void line_graph_draw(struct graph *g, cairo_t *cr);
void line_graph_set_data_count_limit(struct graph *g, int per_label_limit);
void graph_title(struct graph *g, const char *title);
void graph_x_title(struct graph *g, const char *title);
void graph_y_title(struct graph *g, const char *title);
void graph_add_label(struct graph *g, const char *label);
void graph_add_data(struct graph *g, const char *label, const double value);
void graph_add_xy_data(struct graph *g, const char *label,
		const double x, const double y);
void graph_set_color(struct graph *g, const char *label,
		double red, double green, double blue);
void graph_free(struct graph *bg);


#endif

