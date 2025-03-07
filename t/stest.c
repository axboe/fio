#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "../smalloc.h"
#include "../flist.h"
#include "../arch/arch.h"
#include "debug.h"

#define MAGIC1	0xa9b1c8d2
#define MAGIC2	0xf0a1e9b3

#define LOOPS	32
#define MAXSMALLOC	120*1024*1024UL
#define LARGESMALLOC	128*1024U

struct elem {
	unsigned int magic1;
	struct flist_head list;
	unsigned int magic2;
	unsigned int size;
};

static FLIST_HEAD(list);

static int do_rand_allocs(void)
{
	unsigned int i, size, nr, rounds = 0, ret = 0;
	unsigned long total;
	struct elem *e;
	bool error;
	char *c;

	while (rounds++ < LOOPS) {
#ifdef STEST_SEED
		srand(MAGIC1);
#endif
		error = false;
		nr = total = 0;
		while (total < MAXSMALLOC) {
			size = 8 * sizeof(struct elem) + (int) (999.0 * (rand() / (RAND_MAX + 1.0)));
			e = scalloc(1, size);
			if (!e) {
				printf("fail at %lu, size %u\n", total, size);
				ret++;
				break;
			}

			c = (char *)e;
			for (i = 0; i < size; i++) {
				if (*(c+i) != 0) {
					printf("buffer not cleared at %lu, size %u\n", total, size);
					ret++;
					break;
				}
			}

			/* stop the while loop if buffer was not cleared */
			if (i < size)
				break;

			e->magic1 = MAGIC1;
			e->magic2 = MAGIC2;
			e->size = size;
			total += size;
			flist_add_tail(&e->list, &list);
			nr++;
		}

		printf("Got items: %u\n", nr);

		while (!flist_empty(&list)) {
			e = flist_entry(list.next, struct elem, list);
			assert(e->magic1 == MAGIC1);
			assert(e->magic2 == MAGIC2);
			total -= e->size;
			flist_del(&e->list);
			sfree(e);

			if (!error) {
				e = scalloc(1, LARGESMALLOC);
				if (!e) {
					ret++;
					printf("failure allocating %u bytes at %lu allocated during sfree phase\n",
						LARGESMALLOC, total);
					break;
				}

				c = (char *)e;
				for (i = 0; i < LARGESMALLOC; i++) {
					if (*(c+i) != 0) {
						error = true;
						ret++;
						printf("large buffer not cleared at %lu, size %u\n", total, size);
						break;
					}
				}

				sfree(e);
			}
		}
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	arch_init(argv);
	sinit();
	debug_init();

	ret = do_rand_allocs();
	smalloc_debug(0);	/* TODO: check that free and total blocks
				** match */

	scleanup();
	return ret;
}
