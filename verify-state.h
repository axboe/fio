#ifndef FIO_VERIFY_STATE_H
#define FIO_VERIFY_STATE_H

#include <stdint.h>

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
struct thread_io_list {
	uint64_t no_comps;
	uint64_t depth;
	uint64_t numberio;
	uint64_t index;
	struct thread_rand_state rand;
	uint8_t name[64];
	uint64_t offsets[0];
};

struct thread_io_list_v1 {
	uint64_t no_comps;
	uint64_t depth;
	uint64_t numberio;
	uint64_t index;
	struct thread_rand32_state rand;
	uint8_t name[64];
	uint64_t offsets[0];
};

struct all_io_list {
	uint64_t threads;
	struct thread_io_list state[0];
};

#define VSTATE_HDR_VERSION_V1	0x01
#define VSTATE_HDR_VERSION	0x02

struct verify_state_hdr {
	uint64_t version;
	uint64_t size;
	uint64_t crc;
};

#define IO_LIST_ALL		0xffffffff

extern struct all_io_list *get_all_io_list(int, size_t *);
extern void __verify_save_state(struct all_io_list *, const char *);
extern void verify_save_state(int mask);
extern int verify_load_state(struct thread_data *, const char *);
extern void verify_free_state(struct thread_data *);
extern int verify_state_should_stop(struct thread_data *, struct io_u *);
extern void verify_convert_assign_state(struct thread_data *, void *, int);
extern int verify_state_hdr(struct verify_state_hdr *, struct thread_io_list *,
				int *);

static inline size_t __thread_io_list_sz(uint64_t depth)
{
	return sizeof(struct thread_io_list) + depth * sizeof(uint64_t);
}

static inline size_t thread_io_list_sz(struct thread_io_list *s)
{
	return __thread_io_list_sz(le64_to_cpu(s->depth));
}

static inline struct thread_io_list *io_list_next(struct thread_io_list *s)
{
	return (void *) s + thread_io_list_sz(s);
}

static inline void verify_state_gen_name(char *out, size_t size,
					 const char *name, const char *prefix,
					 int num)
{
	snprintf(out, size, "%s-%s-%d-verify.state", prefix, name, num);
	out[size - 1] = '\0';
}

#endif
