#ifndef GRAPH_H
#define GRAPH_H

struct graph;
struct graph_label;

typedef struct graph_label * graph_label_t;

#define GRAPH_DEFAULT_FONT	"Sans 12"

struct graph *graph_new(unsigned int xdim, unsigned int ydim, const char *font);
/* graph_new() Returns a new graph structure of the given dimensions and font */
void graph_set_size(struct graph *g, unsigned int xdim, unsigned int ydim);
/* graph_set_size() Changes the size of a graph to the given dimensions. */ 
void graph_set_position(struct graph *g, double xoffset, double yoffset);
/* graph_set_position() sets the x- and y-offset to translate the graph */
void bar_graph_draw(struct graph *g, cairo_t *cr);
/* bar_graph_draw() draws the given graph as a bar graph */
void line_graph_draw(struct graph *g, cairo_t *cr);
/* line_graph_draw draws the given graph as a line graph */
void line_graph_set_data_count_limit(struct graph *g, int per_label_limit);
/* line_graph_set_data_count_limit() limits the amount of data which can
 * be added to a line graph.  Once the limit is reached, the oldest data 
 * is discarded as new data is added
 */
void graph_set_font(struct graph *g, const char *font);
void graph_title(struct graph *g, const char *title);
/* graph_title() sets the main title of the graph to the given string */
void graph_x_title(struct graph *g, const char *title);
/* graph_x_title() sets the title of the x axis to the given string */
void graph_y_title(struct graph *g, const char *title);
/* graph_y_title() sets the title of the y axis to the given string */
graph_label_t graph_add_label(struct graph *g, const char *label);
/* graph_add_label() adds a new "stream" of data to be graphed.
 * For line charts, each label is a separate line on the graph.
 * For bar charts, each label is a grouping of columns on the x-axis
 * For example:
 *
 *  |  *                          | **
 *  |   *      xxxxxxxx           | **
 *  |    ***  x                   | **              **
 *  |       *x       ****         | **      **      **
 *  |    xxxx*  *****             | ** xx   ** xx   **
 *  |   x     **                  | ** xx   ** xx   ** xx
 *  |  x                          | ** xx   ** xx   ** xx
 *  -----------------------       -------------------------
 *                                    A       B       C
 *
 * For a line graph, the 'x's     For a bar graph, 
 * would be on one "label", and   'A', 'B', and 'C'
 * the '*'s would be on another   are the labels.
 * label.
 */

int graph_add_data(struct graph *g, graph_label_t label, const double value);
/* graph_add_data() is used to add data to the labels of a bar graph */
int graph_add_xy_data(struct graph *g, graph_label_t label,
		const double x, const double y, const char *tooltip);
/* graph_add_xy_data is used to add data to the labels of a line graph */

void graph_set_color(struct graph *g, graph_label_t label,
		double red, double green, double blue);
#define INVISIBLE_COLOR (-1.0)
/* graph_set_color is used to set the color used to plot the data in
 * a line graph.  INVISIBLE_COLOR can be used to plot the data invisibly.
 * Invisible data will have the same effect on the scaling of the axes
 * as visible data.
 */

void graph_free(struct graph *bg);
/* free a graph allocated by graph_new() */

typedef void (*graph_axis_unit_change_callback)(struct graph *g, int power_of_ten);
void graph_x_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f);
void graph_y_axis_unit_change_notify(struct graph *g, graph_axis_unit_change_callback f);
/* The labels used on the x and y axes may be shortened.  You can register for callbacks
 * so that you can know how the labels are shorted, typically used to adjust the axis
 * titles to display the proper units.  The power_of_ten parameter indicates what power
 * of ten the labels have been divided by (9, 6, 3, or 0, corresponding to billions,
 * millions, thousands and ones. 
 */ 

void graph_add_extra_space(struct graph *g, double left_percent, double right_percent,
				double top_percent, double bottom_percent);
/* graph_add_extra_space() adds extra space to edges of the the graph
 * so that the data doesn't go to the very edges.
 */

extern int graph_has_tooltips(struct graph *g);
extern const char *graph_find_tooltip(struct graph *g, int x, int y);
extern int graph_contains_xy(struct graph *p, int x, int y);

extern void graph_set_base_offset(struct graph *g, unsigned int base_offset);
extern void graph_set_graph_all_zeroes(struct graph *g, unsigned int set);

extern void graph_clear_values(struct graph *g);

#endif

