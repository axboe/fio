#ifndef FIO_SKIPLIST_H
#define FIO_SKIPLIST_H

#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>

#define SKIPLIST_MAX_LEVEL 16
#define SKIPLIST_P 0.5  /* Probability for level promotion */

struct skiplist_node {
	uint64_t offset;        /* Start offset of the range */
	uint64_t length;        /* Length of the range */
	void *data;             /* User data pointer */

	/* Variable-length array of forward pointers (atomic for lock-free) */
	int level;
	_Atomic(struct skiplist_node *) forward[];
};

/*
 * Lock-free skiplist structure
 * Uses atomic operations for concurrent access
 */
struct skiplist {
	_Atomic(struct skiplist_node *) header;
	_Atomic int max_level;
	_Atomic uint64_t count;
};

/* Initialize a new skiplist */
struct skiplist *skiplist_new(void);

/* Free the entire skiplist */
void skiplist_free(struct skiplist *list);

/*
 * Insert a range [offset, offset+length) with associated data
 * Returns:
 *   0 on success
 *  -1 if overlapping range exists (overlap check)
 */
int skiplist_insert(struct skiplist *list, uint64_t offset,
                    uint64_t length, void *data);

/*
 * Search for a node that contains the given offset
 * Returns the node if found (where offset is in [node.offset, node.offset+node.length))
 * Returns NULL if not found
 */
struct skiplist_node *skiplist_search(struct skiplist *list, uint64_t offset);

/*
 * Search for any node that overlaps with the range [offset, offset+length)
 * Returns the first overlapping node found, or NULL if no overlap
 */
struct skiplist_node *skiplist_search_overlap(struct skiplist *list,
                                               uint64_t offset, uint64_t length);

/*
 * Delete a range starting at offset
 * Returns:
 *   0 on success
 *  -1 if not found
 */
int skiplist_delete(struct skiplist *list, uint64_t offset);

/*
 * Delete a specific node by pointer (safer for concurrent use)
 * Returns:
 *   0 on success
 *  -1 if node already deleted or not found
 */
int skiplist_delete_node(struct skiplist *list, struct skiplist_node *node);

/*
 * Get the number of nodes in the skiplist
 */
uint64_t skiplist_count(struct skiplist *list);

/*
 * Get the first node in the skiplist (for iteration)
 * Returns NULL if list is empty
 */
struct skiplist_node *skiplist_first(struct skiplist *list);

/*
 * Print skiplist structure (for debugging)
 */
void skiplist_print(struct skiplist *list);

#endif /* FIO_SKIPLIST_H */
