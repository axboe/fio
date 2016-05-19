#ifndef _LINUX_FLIST_H
#define _LINUX_FLIST_H

#include <stdlib.h>

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

/*
 * Simple doubly linked list implementation.
 *
 * Some of the internal functions ("__xxx") are useful when
 * manipulating whole lists rather than single entries, as
 * sometimes we already know the next/prev entries and we can
 * generate better code by using them directly rather than
 * using the generic single-entry routines.
 */

struct flist_head {
	struct flist_head *next, *prev;
};

#define FLIST_HEAD_INIT(name) { &(name), &(name) }

#define FLIST_HEAD(name) \
	struct flist_head name = FLIST_HEAD_INIT(name)

#define INIT_FLIST_HEAD(ptr) do { \
	(ptr)->next = (ptr); (ptr)->prev = (ptr); \
} while (0)

/*
 * Insert a new entry between two known consecutive entries.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __flist_add(struct flist_head *new_entry,
			       struct flist_head *prev,
			       struct flist_head *next)
{
	next->prev = new_entry;
	new_entry->next = next;
	new_entry->prev = prev;
	prev->next = new_entry;
}

/**
 * flist_add - add a new entry
 * @new_entry: new entry to be added
 * @head: list head to add it after
 *
 * Insert a new entry after the specified head.
 * This is good for implementing stacks.
 */
static inline void flist_add(struct flist_head *new_entry,
                             struct flist_head *head)
{
	__flist_add(new_entry, head, head->next);
}

static inline void flist_add_tail(struct flist_head *new_entry,
				  struct flist_head *head)
{
	__flist_add(new_entry, head->prev, head);
}

/*
 * Delete a list entry by making the prev/next entries
 * point to each other.
 *
 * This is only for internal list manipulation where we know
 * the prev/next entries already!
 */
static inline void __flist_del(struct flist_head *prev,
			       struct flist_head * next)
{
	next->prev = prev;
	prev->next = next;
}

/**
 * flist_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: flist_empty on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void flist_del(struct flist_head *entry)
{
	__flist_del(entry->prev, entry->next);
	entry->next = NULL;
	entry->prev = NULL;
}

/**
 * flist_del_init - deletes entry from list and reinitialize it.
 * @entry: the element to delete from the list.
 */
static inline void flist_del_init(struct flist_head *entry)
{
	__flist_del(entry->prev, entry->next);
	INIT_FLIST_HEAD(entry);
}

/**
 * flist_empty - tests whether a list is empty
 * @head: the list to test.
 */
static inline int flist_empty(const struct flist_head *head)
{
	return head->next == head;
}

static inline void __flist_splice(const struct flist_head *list,
				  struct flist_head *prev,
				  struct flist_head *next)
{
	struct flist_head *first = list->next;
	struct flist_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void flist_splice(const struct flist_head *list,
				struct flist_head *head)
{
	if (!flist_empty(list))
		__flist_splice(list, head, head->next);
}

static inline void flist_splice_tail(struct flist_head *list,
				     struct flist_head *head)
{
	if (!flist_empty(list))
		__flist_splice(list, head->prev, head);
}

static inline void flist_splice_tail_init(struct flist_head *list,
					  struct flist_head *head)
{
	if (!flist_empty(list)) {
		__flist_splice(list, head->prev, head);
		INIT_FLIST_HEAD(list);
	}
}

static inline void flist_splice_init(struct flist_head *list,
				    struct flist_head *head)
{
	if (!flist_empty(list)) {
		__flist_splice(list, head, head->next);
		INIT_FLIST_HEAD(list);
	}
}

/**
 * flist_entry - get the struct for this entry
 * @ptr:	the &struct flist_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the flist_struct within the struct.
 */
#define flist_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define flist_first_entry(ptr, type, member) \
	flist_entry((ptr)->next, type, member)

#define flist_last_entry(ptr, type, member) \
	flist_entry((ptr)->prev, type, member)

/**
 * flist_for_each	-	iterate over a list
 * @pos:	the &struct flist_head to use as a loop counter.
 * @head:	the head for your list.
 */
#define flist_for_each(pos, head) \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * flist_for_each_safe	-	iterate over a list safe against removal of list entry
 * @pos:	the &struct flist_head to use as a loop counter.
 * @n:		another &struct flist_head to use as temporary storage
 * @head:	the head for your list.
 */
#define flist_for_each_safe(pos, n, head) \
	for (pos = (head)->next, n = pos->next; pos != (head); \
		pos = n, n = pos->next)

extern void flist_sort(void *priv, struct flist_head *head,
	int (*cmp)(void *priv, struct flist_head *a, struct flist_head *b));

#endif
