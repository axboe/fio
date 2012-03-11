#ifndef GRAPH_H
#define GRAPH_H

struct graph;

#define INVISIBLE_COLOR (-1.0)

struct graph *graph_new(unsigned int xdim, unsigned int ydim, const char *font);
void graph_set_size(struct graph *g, unsigned int xdim, unsigned int ydim);
void bar_graph_draw(struct graph *g, cairo_t *cr);
void line_graph_draw(struct graph *g, cairo_t *cr);
void line_graph_set_data_count_limit(struct graph *g, int per_label_limit);
void graph_title(struct graph *g, const char *title);
void graph_x_title(struct graph *g, const char *title);
void graph_y_title(struct graph *g, const char *title);
void graph_add_label(struct graph *g, const char *label);
int graph_add_data(struct graph *g, const char *label, const double value);
int graph_add_xy_data(struct graph *g, const char *label,
		const double x, const double y);
void graph_set_color(struct graph *g, const char *label,
		double red, double green, double blue);
void graph_free(struct graph *bg);

typedef void (*graph_axis_unit_change_callback)(struct graph *g, int power_of_ten);
void graph_x_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f);
void graph_y_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f);

#endif

