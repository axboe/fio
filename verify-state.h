#ifndef FIO_VERIFY_STATE_H
#define FIO_VERIFY_STATE_H

#include <stdint.h>
#include <string.h>
#include <limits.h>

struct thread_rand32_state {
	uint32_t s[4];
};

struct thread_rand64_state {
	uint64_t s[6];
};

struct thread_rand_state {
	uint64_t use64;
	union {
		struct thread_rand32_state state32;
		struct thread_rand64_state state64;
	};
};

/*
 * For dumping current write state
 */
struct file_comp {
	uint64_t fileno;
	uint64_t offset;
};

struct thread_io_list {
	uint64_t no_comps;
	uint32_t depth;
	uint32_t nofiles;
	uint64_t numberio;
	uint64_t index;
	struct thread_rand_state rand;
	uint8_t name[64];
	struct file_comp comps[0];
};

struct all_io_list {
	uint64_t threads;
	struct thread_io_list state[0];
};

#define VSTATE_HDR_VERSION	0x03

struct verify_state_hdr {
	uint64_t version;
	uint64_t size;
	uint64_t crc;
};

#define IO_LIST_ALL		0xffffffff

struct io_u;
extern struct all_io_list *get_all_io_list(int, size_t *);
extern void __verify_save_state(struct all_io_list *, const char *);
extern void verify_save_state(int mask);
extern int verify_load_state(struct thread_data *, const char *);
extern void verify_free_state(struct thread_data *);
extern int verify_state_should_stop(struct thread_data *, struct io_u *);
extern void verify_assign_state(struct thread_data *, void *);
extern int verify_state_hdr(struct verify_state_hdr *, struct thread_io_list *);

static inline size_t __thread_io_list_sz(uint32_t depth, uint32_t nofiles)
{
	return sizeof(struct thread_io_list) + depth * nofiles * sizeof(struct file_comp);
}

static inline size_t thread_io_list_sz(struct thread_io_list *s)
{
	return __thread_io_list_sz(le32_to_cpu(s->depth), le32_to_cpu(s->nofiles));
}

static inline struct thread_io_list *io_list_next(struct thread_io_list *s)
{
	return (void *) s + thread_io_list_sz(s);
}

static inline void verify_state_gen_name(char *out, size_t size,
					 const char *name, const char *prefix,
					 int num)
{
	char ename[PATH_MAX];
	char *ptr;

	/*
	 * Escape '/', just turn them into '.'
	 */
	ptr = ename;
	do {
		*ptr = *name;
		if (*ptr == '\0')
			break;
		else if (*ptr == '/')
			*ptr = '.';
		ptr++;
		name++;
	} while (1);

	snprintf(out, size, "%s-%s-%d-verify.state", prefix, ename, num);
	out[size - 1] = '\0';
}

#endif
