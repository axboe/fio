#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <assert.h>
#include "skiplist.h"

/* Marked pointer handling - use LSB for marking */
#define MARK_MASK    ((uintptr_t)0x1)
#define PTR_MASK     (~MARK_MASK)

static inline bool is_marked(struct skiplist_node *ptr)
{
	return ((uintptr_t)ptr & MARK_MASK) != 0;
}

static inline struct skiplist_node *get_unmarked(struct skiplist_node *ptr)
{
	return (struct skiplist_node *)((uintptr_t)ptr & PTR_MASK);
}

static inline struct skiplist_node *get_marked(struct skiplist_node *ptr)
{
	return (struct skiplist_node *)((uintptr_t)ptr | MARK_MASK);
}

/*
 * Generate a random level for a new node using geometric distribution
 */
static int random_level(void)
{
	int level = 1;

	while (level < SKIPLIST_MAX_LEVEL && ((double)rand() / RAND_MAX) < SKIPLIST_P)
		level++;

	return level;
}

/*
 * Create a new skiplist node
 */
static struct skiplist_node *create_node(uint64_t offset, uint64_t length,
                                         void *data, int level)
{
	size_t size = sizeof(struct skiplist_node) +
	              level * sizeof(_Atomic(struct skiplist_node *));
	struct skiplist_node *node = malloc(size);

	if (!node)
		return NULL;

	node->offset = offset;
	node->length = length;
	node->data = data;
	node->level = level;

	for (int i = 0; i < level; i++)
		atomic_init(&node->forward[i], NULL);

	return node;
}

/*
 * Initialize a new skiplist
 */
struct skiplist *skiplist_new(void)
{
	struct skiplist *list = malloc(sizeof(struct skiplist));
	struct skiplist_node *header;
	static atomic_bool seeded = false;
	bool expected = false;

	if (!list)
		return NULL;

	/* Create sentinel header node with max level */
	header = create_node(0, 0, NULL, SKIPLIST_MAX_LEVEL);
	if (!header) {
		free(list);
		return NULL;
	}

	atomic_init(&list->header, header);
	atomic_init(&list->max_level, 1);
	atomic_init(&list->count, 0);

	/* Seed random number generator */
	if (atomic_compare_exchange_strong(&seeded, &expected, true))
		srand(time(NULL));

	return list;
}

/*
 * Free the entire skiplist
 */
void skiplist_free(struct skiplist *list)
{
	struct skiplist_node *header;
	struct skiplist_node *current;

	if (!list)
		return;

	header = atomic_load(&list->header);
	current = get_unmarked(atomic_load(&header->forward[0]));

	while (current) {
		struct skiplist_node *next = get_unmarked(atomic_load(&current->forward[0]));
		free(current);
		current = next;
	}

	free(header);
	free(list);
}

/*
 * Check if two ranges overlap
 */
static inline bool ranges_overlap(uint64_t offset1, uint64_t length1,
                                  uint64_t offset2, uint64_t length2)
{
	uint64_t end1 = offset1 + length1;
	uint64_t end2 = offset2 + length2;

	return (offset1 < end2) && (offset2 < end1);
}

/*
 * Find predecessors and successors for a given key (offset)
 */
static bool find(struct skiplist *list, uint64_t offset,
                 struct skiplist_node **preds, struct skiplist_node **succs)
{
	struct skiplist_node *pred, *curr, *succ;
	int level;
	bool found = false;

retry:
	pred = atomic_load(&list->header);

	for (level = SKIPLIST_MAX_LEVEL - 1; level >= 0; level--) {
		curr = get_unmarked(atomic_load(&pred->forward[level]));

		while (curr != NULL) {
			succ = atomic_load(&curr->forward[level]);

			/* Remove marked nodes we encounter */
			while (is_marked(succ)) {
				struct skiplist_node *unmarked_succ = get_unmarked(succ);

				/* Try to physically remove the marked node */
				if (!atomic_compare_exchange_strong(&pred->forward[level],
				                                     &curr, unmarked_succ)) {
					goto retry;
				}

				curr = get_unmarked(atomic_load(&pred->forward[level]));
				if (curr == NULL)
					break;
				succ = atomic_load(&curr->forward[level]);
			}

			if (curr == NULL)
				break;

			/* Move forward if current offset is less than target */
			if (curr->offset < offset) {
				pred = curr;
				curr = get_unmarked(succ);
			} else {
				break;
			}
		}

		if (preds)
			preds[level] = pred;
		if (succs)
			succs[level] = curr;
	}

	/* Check if we found exact match */
	if (curr && curr->offset == offset && !is_marked(atomic_load(&curr->forward[0])))
		found = true;

	return found;
}

/*
 * Search for a node that contains the given offset
 */
struct skiplist_node *skiplist_search(struct skiplist *list, uint64_t offset)
{
	struct skiplist_node *pred, *curr;

	if (!list)
		return NULL;

	pred = atomic_load(&list->header);

	for (int level = SKIPLIST_MAX_LEVEL - 1; level >= 0; level--) {
		curr = get_unmarked(atomic_load(&pred->forward[level]));

		while (curr != NULL) {
			if (is_marked(atomic_load(&curr->forward[0]))) {
				/* Skip marked node - move to next */
				curr = get_unmarked(atomic_load(&curr->forward[level]));
				continue;
			}

			/* Check if offset falls within this node's range */
			if (offset >= curr->offset && offset < curr->offset + curr->length)
				return curr;

			if (curr->offset > offset)
				break;

			pred = curr;
			curr = get_unmarked(atomic_load(&curr->forward[level]));
		}
	}

	return NULL;
}

/*
 * Search for any node that overlaps with the range [offset, offset+length)
 */
struct skiplist_node *skiplist_search_overlap(struct skiplist *list,
                                               uint64_t offset, uint64_t length)
{
	struct skiplist_node *pred, *curr;

	if (!list)
		return NULL;

	pred = atomic_load(&list->header);

	for (int level = SKIPLIST_MAX_LEVEL - 1; level >= 0; level--) {
		curr = get_unmarked(atomic_load(&pred->forward[level]));

		while (curr != NULL) {
			if (is_marked(atomic_load(&curr->forward[0]))) {
				/* Skip marked node - move to next */
				curr = get_unmarked(atomic_load(&curr->forward[level]));
				continue;
			}

			/* Check for overlap */
			if (ranges_overlap(offset, length, curr->offset, curr->length))
				return curr;

			/* If current node's start is beyond our range, no more overlaps possible */
			if (curr->offset >= offset + length)
				break;

			pred = curr;
			curr = get_unmarked(atomic_load(&curr->forward[level]));
		}
	}

	return NULL;
}

/*
 * Insert a range [offset, offset+length) with associated data
 */
int skiplist_insert(struct skiplist *list, uint64_t offset,
                    uint64_t length, void *data)
{
	struct skiplist_node *preds[SKIPLIST_MAX_LEVEL];
	struct skiplist_node *succs[SKIPLIST_MAX_LEVEL];
	struct skiplist_node *new_node;
	int level, max_level;

	if (!list)
		return -1;

	/* Generate random level for new node */
	level = random_level();

	while (true) {
		struct skiplist_node *expected;
		bool found;

		/*
		 * CRITICAL: Check for overlaps on every retry to prevent race conditions
		 * Two threads could pass initial check simultaneously then both insert
		 */
		if (skiplist_search_overlap(list, offset, length) != NULL)
			return -1;

		/* Find position to insert */
		found = find(list, offset, preds, succs);

		/* If already exists, fail */
		if (found)
			return -1;

		/* Double-check for overlaps with both predecessors and successors */
		for (int i = 0; i < level && i < SKIPLIST_MAX_LEVEL; i++) {
			/* Check successor overlap */
			if (succs[i] && ranges_overlap(offset, length,
			                               succs[i]->offset, succs[i]->length))
				return -1;

			/* Check predecessor overlap (skip header node) */
			if (preds[i] && preds[i] != atomic_load(&list->header) &&
			    ranges_overlap(offset, length,
			                   preds[i]->offset, preds[i]->length))
				return -1;
		}

		/* Create new node */
		new_node = create_node(offset, length, data, level);
		if (!new_node)
			return -1;

		/* Link new node to successors */
		for (int i = 0; i < level; i++)
			atomic_store(&new_node->forward[i], succs[i]);

		/* Try to insert at level 0 first (most critical) */
		expected = succs[0];
		if (!atomic_compare_exchange_strong(&preds[0]->forward[0],
		                                     &expected, new_node)) {
			/* Failed, retry */
			free(new_node);
			continue;
		}

		/* Successfully inserted at level 0, now insert at higher levels */
		for (int i = 1; i < level; i++) {
			while (true) {
				expected = succs[i];
				if (atomic_compare_exchange_strong(&preds[i]->forward[i],
				                                    &expected, new_node))
					break;

				/* Retry finding position for this level */
				find(list, offset, preds, succs);
			}
		}

		/* Update max level if necessary */
		max_level = atomic_load(&list->max_level);
		if (level > max_level) {
			atomic_compare_exchange_strong(&list->max_level, &max_level, level);
		}

		atomic_fetch_add(&list->count, 1);
		return 0;
	}
}

/*
 * Delete a range starting at offset
 */
int skiplist_delete(struct skiplist *list, uint64_t offset)
{
	struct skiplist_node *preds[SKIPLIST_MAX_LEVEL];
	struct skiplist_node *succs[SKIPLIST_MAX_LEVEL];
	struct skiplist_node *victim;

	if (!list)
		return -1;

	while (true) {
		struct skiplist_node *succ;
		/* Find the node to delete */
		bool found = find(list, offset, preds, succs);

		if (!found)
			return -1;

		victim = succs[0];

		/* Logically delete by marking all forward pointers from top to bottom */
		for (int level = victim->level - 1; level >= 1; level--) {
			do {
				succ = atomic_load(&victim->forward[level]);
				if (is_marked(succ))
					break;
			} while (!atomic_compare_exchange_strong(&victim->forward[level],
			                                          &succ, get_marked(succ)));
		}

		/* Mark level 0 last */
		succ = atomic_load(&victim->forward[0]);
		while (true) {
			if (is_marked(succ))
				return -1;  /* Already deleted by another thread */

			if (atomic_compare_exchange_strong(&victim->forward[0],
			                                    &succ, get_marked(succ)))
				break;
		}

		/* Physical deletion will be done by find() on next traversal */
		atomic_fetch_sub(&list->count, 1);

		/* Try to help with physical deletion */
		find(list, offset, NULL, NULL);

		return 0;
	}
}

/*
 * Delete a specific node by pointer (thread-safe)
 * This is safer than delete-by-offset in concurrent scenarios
 * where the same offset might be reused
 */
int skiplist_delete_node(struct skiplist *list, struct skiplist_node *target)
{
	struct skiplist_node *succ;

	if (!list || !target)
		return -1;

	/* Check if already marked for deletion */
	if (is_marked(atomic_load(&target->forward[0])))
		return -1;

	/* Logically delete by marking all forward pointers from top to bottom */
	for (int level = target->level - 1; level >= 1; level--) {
		do {
			succ = atomic_load(&target->forward[level]);
			if (is_marked(succ))
				break;
		} while (!atomic_compare_exchange_strong(&target->forward[level],
		                                          &succ, get_marked(succ)));
	}

	/* Mark level 0 last */
	succ = atomic_load(&target->forward[0]);
	while (true) {
		if (is_marked(succ))
			return -1;  /* Already deleted by another thread */

		if (atomic_compare_exchange_strong(&target->forward[0],
		                                    &succ, get_marked(succ)))
			break;
	}

	/* Physical deletion will be done by find() on next traversal */
	atomic_fetch_sub(&list->count, 1);

	/* Try to help with physical deletion */
	find(list, target->offset, NULL, NULL);

	return 0;
}

/*
 * Get the number of nodes in the skiplist
 */
uint64_t skiplist_count(struct skiplist *list)
{
	if (!list)
		return 0;

	return atomic_load(&list->count);
}

/*
 * Get the first node in the skiplist
 */
struct skiplist_node *skiplist_first(struct skiplist *list)
{
	struct skiplist_node *header, *first;

	if (!list)
		return NULL;

	header = atomic_load(&list->header);
	first = get_unmarked(atomic_load(&header->forward[0]));

	/* Skip marked nodes */
	while (first && is_marked(atomic_load(&first->forward[0]))) {
		first = get_unmarked(atomic_load(&first->forward[0]));
	}

	return first;
}

/*
 * Print skiplist structure (for debugging)
 */
void skiplist_print(struct skiplist *list)
{
	struct skiplist_node *header;
	struct skiplist_node *current;

	if (!list)
		return;

	header = atomic_load(&list->header);
	current = get_unmarked(atomic_load(&header->forward[0]));

	printf("Skiplist (count=%llu, max_level=%d):\n",
	       (unsigned long long)atomic_load(&list->count), atomic_load(&list->max_level));

	while (current) {
		printf("  [%llu, %llu) level=%d data=%p marked=%d\n",
		       (unsigned long long)current->offset,
		       (unsigned long long)(current->offset + current->length),
		       current->level,
		       current->data,
		       is_marked(atomic_load(&current->forward[0])) ? 1 : 0);

		current = get_unmarked(atomic_load(&current->forward[0]));
	}
}
