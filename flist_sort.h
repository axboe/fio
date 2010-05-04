#ifndef FIO_FLIST_SORT_H
#define FIO_FLIST_SORT_H

struct flist_head;

void flist_sort(void *priv, struct flist_head *head,
	       int (*cmp)(void *priv, struct flist_head *a,
			  struct flist_head *b));
#endif
