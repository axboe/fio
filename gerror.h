#ifndef GFIO_ERROR_H
#define GFIO_ERROR_H

extern void gfio_report_error(struct gui_entry *ge, const char *format, ...);
extern void gfio_report_info(struct gui *ui, const char *title, const char *message);

#endif
