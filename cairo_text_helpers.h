#ifndef CAIRO_TEXT_HELPERS_H
#define CAIRO_TEXT_HELPERS_H

#include <cairo.h>

void draw_centered_text(cairo_t *cr, const char *font, double x, double y,
			       double fontsize, const char *text);

void draw_right_justified_text(cairo_t *cr, const char *font,
				double x, double y,
				double fontsize, const char *text);

void draw_left_justified_text(cairo_t *cr, const char *font,
				double x, double y,
				double fontsize, const char *text);

void draw_vertical_centered_text(cairo_t *cr, const char *font, double x,
					double y, double fontsize,
					const char *text);
#endif
