/*
 * Dump the contents of a verify state file in plain text
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include "../log.h"
#include "../os/os.h"
#include "../verify-state.h"
#include "../crc/crc32c.h"
#include "debug.h"

static void show_s(struct thread_io_list *s, unsigned int no_s)
{
	int i;

	printf("Thread:\t\t%u\n", no_s);
	printf("Name:\t\t%s\n", s->name);
	printf("Completions:\t%llu\n", (unsigned long long) s->no_comps);
	printf("Depth:\t\t%llu\n", (unsigned long long) s->depth);
	printf("Number IOs:\t%llu\n", (unsigned long long) s->numberio);
	printf("Index:\t\t%llu\n", (unsigned long long) s->index);

	printf("Completions:\n");
	if (!s->no_comps)
		return;
	for (i = s->no_comps - 1; i >= 0; i--) {
		printf("\t(file=%2llu) %llu\n",
				(unsigned long long) s->comps[i].fileno,
				(unsigned long long) s->comps[i].offset);
	}
}

static void show(struct thread_io_list *s, size_t size)
{
	int no_s;

	no_s = 0;
	do {
		int i;

		s->no_comps = le64_to_cpu(s->no_comps);
		s->depth = le32_to_cpu(s->depth);
		s->nofiles = le32_to_cpu(s->nofiles);
		s->numberio = le64_to_cpu(s->numberio);
		s->index = le64_to_cpu(s->index);

		for (i = 0; i < s->no_comps; i++) {
			s->comps[i].fileno = le64_to_cpu(s->comps[i].fileno);
			s->comps[i].offset = le64_to_cpu(s->comps[i].offset);
		}

		show_s(s, no_s);
		no_s++;
		size -= __thread_io_list_sz(s->depth, s->nofiles);
		s = (void *) s + __thread_io_list_sz(s->depth, s->nofiles);
	} while (size != 0);
}

static void show_verify_state(void *buf, size_t size)
{
	struct verify_state_hdr *hdr = buf;
	struct thread_io_list *s;
	uint32_t crc;

	hdr->version = le64_to_cpu(hdr->version);
	hdr->size = le64_to_cpu(hdr->size);
	hdr->crc = le64_to_cpu(hdr->crc);

	printf("Version:\t0x%x\n", (unsigned int) hdr->version);
	printf("Size:\t\t%u\n", (unsigned int) hdr->size);
	printf("CRC:\t\t0x%x\n", (unsigned int) hdr->crc);

	size -= sizeof(*hdr);
	if (hdr->size != size) {
		log_err("Size mismatch\n");
		return;
	}

	s = buf + sizeof(*hdr);
	crc = fio_crc32c((unsigned char *) s, hdr->size);
	if (crc != hdr->crc) {
		log_err("crc mismatch %x != %x\n", crc, (unsigned int) hdr->crc);
		return;
	}

	if (hdr->version == 0x03)
		show(s, size);
	else
		log_err("Unsupported version %d\n", (int) hdr->version);
}

static int show_file(const char *file)
{
	struct stat sb;
	void *buf;
	int ret, fd;

	fd = open(file, O_RDONLY);
	if (fd < 0) {
		log_err("open %s: %s\n", file, strerror(errno));
		return 1;
	}

	if (fstat(fd, &sb) < 0) {
		log_err("stat: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	buf = malloc(sb.st_size);
	ret = read(fd, buf, sb.st_size);
	if (ret < 0) {
		log_err("read: %s\n", strerror(errno));
		close(fd);
		return 1;
	} else if (ret != sb.st_size) {
		log_err("Short read\n");
		close(fd);
		return 1;
	}

	close(fd);
	show_verify_state(buf, sb.st_size);

	free(buf);
	return 0;
}

int main(int argc, char *argv[])
{
	int i, ret;

	debug_init();

	if (argc < 2) {
		log_err("Usage: %s <state file>\n", argv[0]);
		return 1;
	}

	ret = 0;
	for (i = 1; i < argc; i++) {
		ret = show_file(argv[i]);
		if (ret)
			break;
	}

	return ret;
}
