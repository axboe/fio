#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../smalloc.h"
#include "../flist.h"

FILE *f_err;
struct timeval *fio_tv = NULL;
unsigned int fio_debug = 0;

#define MAGIC1	0xa9b1c8d2
#define MAGIC2	0xf0a1e9b3

#define LOOPS	32

struct elem {
	unsigned int magic1;
	struct flist_head list;
	unsigned int magic2;
};

FLIST_HEAD(list);

static int do_rand_allocs(void)
{
	unsigned int size, nr, rounds = 0;
	unsigned long total;
	struct elem *e;

	while (rounds++ < LOOPS) {
#ifdef STEST_SEED
		srand(MAGIC1);
#endif
		nr = total = 0;
		while (total < 128*1024*1024UL) {
			size = 8 * sizeof(struct elem) + (int) (999.0 * (rand() / (RAND_MAX + 1.0)));
			e = smalloc(size);
			if (!e) {
				printf("fail at %lu, size %u\n", total, size);
				break;
			}
			e->magic1 = MAGIC1;
			e->magic2 = MAGIC2;
			total += size;
			flist_add_tail(&e->list, &list);
			nr++;
		}

		printf("Got items: %u\n", nr);

		while (!flist_empty(&list)) {
			e = flist_entry(list.next, struct elem, list);
			assert(e->magic1 == MAGIC1);
			assert(e->magic2 == MAGIC2);
			flist_del(&e->list);
			sfree(e);
		}
	}

	return 0;
}

static int do_specific_alloc(unsigned long size)
{
	void *ptr;

	ptr = smalloc(size);
	sfree(ptr);
	return 0;
}

int main(int argc, char *argv[])
{
	f_err = stderr;

	sinit();

	do_rand_allocs();

	/* smalloc bug, commit 271067a6 */
	do_specific_alloc(671386584);

	scleanup();
	return 0;
}

void __dprint(int type, const char *str, ...)
{
}
