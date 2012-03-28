#include <cairo.h>
#include <gtk/gtk.h>
#include <math.h>

static void draw_aligned_text(cairo_t *cr, const char *font, double x, double y,
			       double fontsize, const char *text, int alignment)
{
#define CENTERED 0
#define LEFT_JUSTIFIED 1
#define RIGHT_JUSTIFIED 2

	double factor, direction;
	cairo_text_extents_t extents;

	switch (alignment) {
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
			factor = 0.0;
			break;
	}
	cairo_select_font_face(cr, font, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);

	cairo_set_font_size(cr, fontsize);
	cairo_text_extents(cr, text, &extents);
	x = x + direction * (factor * extents.width  + extents.x_bearing);
	y = y - (extents.height / 2 + extents.y_bearing);

	cairo_move_to(cr, x, y);
	cairo_show_text(cr, text);
}

void draw_centered_text(cairo_t *cr, const char *font, double x, double y,
			       double fontsize, const char *text)
{
	draw_aligned_text(cr, font, x, y, fontsize, text, CENTERED);
}

void draw_right_justified_text(cairo_t *cr, const char *font,
				double x, double y,
				double fontsize, const char *text)
{
	draw_aligned_text(cr, font, x, y, fontsize, text, RIGHT_JUSTIFIED);
}

void draw_left_justified_text(cairo_t *cr, const char *font,
				double x, double y,
				double fontsize, const char *text)
{
	draw_aligned_text(cr, font, x, y, fontsize, text, LEFT_JUSTIFIED);
}

void draw_vertical_centered_text(cairo_t *cr, const char *font, double x,
					double y, double fontsize,
					const char *text)
{
	double sx, sy;
	cairo_text_extents_t extents;

	cairo_select_font_face(cr, font, CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);

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

