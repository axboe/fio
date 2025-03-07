#ifndef _LINUX_PRIO_TREE_H
#define _LINUX_PRIO_TREE_H

#include <inttypes.h>

struct prio_tree_node {
	struct prio_tree_node	*left;
	struct prio_tree_node	*right;
	struct prio_tree_node	*parent;
	uint64_t		start;
	uint64_t		last;	/* last location _in_ interval */
};

struct prio_tree_root {
	struct prio_tree_node	*prio_tree_node;
	unsigned short 		index_bits;
};

struct prio_tree_iter {
	struct prio_tree_node	*cur;
	unsigned long		mask;
	unsigned long		value;
	int			size_level;

	struct prio_tree_root	*root;
	uint64_t		r_index;
	uint64_t		h_index;
};

static inline void prio_tree_iter_init(struct prio_tree_iter *iter,
		struct prio_tree_root *root, uint64_t r_index, uint64_t h_index)
{
	iter->root = root;
	iter->r_index = r_index;
	iter->h_index = h_index;
	iter->cur = NULL;
}

#define INIT_PRIO_TREE_ROOT(ptr)	\
do {					\
	(ptr)->prio_tree_node = NULL;	\
	(ptr)->index_bits = 1;		\
} while (0)

#define INIT_PRIO_TREE_NODE(ptr)				\
do {								\
	(ptr)->left = (ptr)->right = (ptr)->parent = (ptr);	\
} while (0)

#define INIT_PRIO_TREE_ITER(ptr)	\
do {					\
	(ptr)->cur = NULL;		\
	(ptr)->mask = 0UL;		\
	(ptr)->value = 0UL;		\
	(ptr)->size_level = 0;		\
} while (0)

#define prio_tree_entry(ptr, type, member) \
       ((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

static inline int prio_tree_empty(const struct prio_tree_root *root)
{
	return root->prio_tree_node == NULL;
}

static inline int prio_tree_root(const struct prio_tree_node *node)
{
	return node->parent == node;
}

static inline int prio_tree_left_empty(const struct prio_tree_node *node)
{
	return node->left == node;
}

static inline int prio_tree_right_empty(const struct prio_tree_node *node)
{
	return node->right == node;
}


struct prio_tree_node *prio_tree_replace(struct prio_tree_root *root,
                struct prio_tree_node *old, struct prio_tree_node *node);
struct prio_tree_node *prio_tree_insert(struct prio_tree_root *root,
                struct prio_tree_node *node);
void prio_tree_remove(struct prio_tree_root *root, struct prio_tree_node *node);
struct prio_tree_node *prio_tree_next(struct prio_tree_iter *iter);

#endif /* _LINUX_PRIO_TREE_H */
