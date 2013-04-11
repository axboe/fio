#ifndef GFIO_CLIENT_H
#define GFIO_CLIENT_H

extern struct client_ops gfio_client_ops;

extern void gfio_display_end_results(struct gfio_client *);

#define GFIO_READ_R	0.13
#define GFIO_READ_G	0.54
#define GFIO_READ_B	0.13
#define GFIO_WRITE_R	1.00
#define GFIO_WRITE_G	0.00
#define GFIO_WRITE_B	0.00
#define GFIO_TRIM_R	0.24
#define GFIO_TRIM_G	0.18
#define GFIO_TRIM_B	0.52

#endif
