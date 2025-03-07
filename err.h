#ifndef FIO_ERR_H
#define FIO_ERR_H

/*
 * Kernel pointers have redundant information, so we can use a
 * scheme where we can return either an error code or a dentry
 * pointer with the same return value.
 *
 * This should be a per-architecture thing, to allow different
 * error and pointer decisions.
 */
#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) ((x) >= (uintptr_t)-MAX_ERRNO)

static inline void *ERR_PTR(uintptr_t error)
{
	return (void *) error;
}

static inline uintptr_t PTR_ERR(const void *ptr)
{
	return (uintptr_t) ptr;
}

static inline uintptr_t IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((uintptr_t)ptr);
}

static inline uintptr_t IS_ERR_OR_NULL(const void *ptr)
{
	return !ptr || IS_ERR_VALUE((uintptr_t)ptr);
}

static inline int PTR_ERR_OR_ZERO(const void *ptr)
{
	if (IS_ERR(ptr))
		return PTR_ERR(ptr);
	else
		return 0;
}

#endif
