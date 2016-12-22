#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

static struct thread_data {
	unsigned long mib;
} td;

static void *worker(void *data)
{
	struct thread_data *td = data;
	unsigned long index;
	size_t size;
	char *buf;
	int i, first = 1;

	size = td->mib * 1024UL * 1024UL;
	buf = malloc(size);

	for (i = 0; i < 100000; i++) {
		for (index = 0; index + 4096 < size; index += 4096)
			memset(&buf[index+512], 0x89, 512);
		if (first) {
			printf("loop%d: did %lu MiB\n", i+1, size/(1024UL*1024UL));
			first = 0;
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	unsigned long mib, threads;
	pthread_t *pthreads;
	int i;

	if (argc < 3) {
		printf("%s: <MiB per thread> <threads>\n", argv[0]);
		return 1;
	}

	mib = strtoul(argv[1], NULL, 10);
	threads = strtoul(argv[2], NULL, 10);

	pthreads = calloc(threads, sizeof(pthread_t));
	td.mib = mib;

	for (i = 0; i < threads; i++)
		pthread_create(&pthreads[i], NULL, worker, &td);

	for (i = 0; i < threads; i++) {
		void *ret;

		pthread_join(pthreads[i], &ret);
	}
	return 0;
}
