#include <math.h>
#include <string.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include "ieee754.h"
#include "../log.h"
#include "zipf.h"
#include "../minmax.h"
#include "../hash.h"
#include "../os/os.h"

struct fio_zipf_disk {
	uint64_t ver_magic;
	uint64_t nranges;
	uint64_t zetan;
};

#define FIO_ZIPF_DISK_MAGIC	0x7a697066
#define FIO_ZIPF_DISK_VER	1
#define FIO_ZIPF_MAGIC		((FIO_ZIPF_DISK_MAGIC << 16) | FIO_ZIPF_DISK_VER)

static void write_zipf(struct zipf_state *zs)
{
	struct fio_zipf_disk f;
	char tmp[80];
	int fd;

	sprintf(tmp, "fio.zipf.%f.%llu", zs->theta, (unsigned long long) zs->nranges);
	fd = open(tmp, O_CREAT | O_WRONLY, 0644);
	if (fd == -1)
		return;

	f.ver_magic = __cpu_to_le64(FIO_ZIPF_MAGIC);
	f.nranges = __cpu_to_le64(zs->nranges);
	f.zetan = __cpu_to_le64(fio_double_to_uint64(zs->zetan));
	if (write(fd, &f, sizeof(f)) != sizeof(f))
		unlink(tmp);

	close(fd);
}

static void zipf_update(struct zipf_state *zs)
{
	unsigned int i;

	log_info("fio: generating zetan for theta=%f, ranges=%lu\n", zs->theta, zs->nranges);

	for (i = 0; i < zs->nranges; i++)
		zs->zetan += pow(1.0 / (double) (i + 1), zs->theta);

	write_zipf(zs);
}

static void zipf_load_gen_zeta(struct zipf_state *zs)
{
	struct fio_zipf_disk f;
	char tmp[80];
	int fd;

	sprintf(tmp, "fio.zipf.%f.%llu", zs->theta, (unsigned long long) zs->nranges);
	fd = open(tmp, O_RDONLY);
	if (fd == -1) {
punt:
		zipf_update(zs);
		return;
	}

	if (read(fd, &f, sizeof(f)) != sizeof(f)) {
		close(fd);
		goto punt;
	}

	close(fd);

	f.ver_magic = le64_to_cpu(f.ver_magic);
	f.nranges = le64_to_cpu(f.nranges);
	f.zetan = le64_to_cpu(f.zetan);

	if (f.ver_magic != FIO_ZIPF_MAGIC) {
		unlink(tmp);
		goto punt;
	}

	zs->zetan = fio_uint64_to_double(f.zetan);
	zs->nranges = f.nranges;
}

static void shared_rand_init(struct zipf_state *zs, unsigned long nranges,
			     unsigned int seed)
{
	memset(zs, 0, sizeof(*zs));
	zs->nranges = nranges;

	init_rand_seed(&zs->rand, seed);
	zs->rand_off = __rand(&zs->rand);
}

void zipf_init(struct zipf_state *zs, unsigned long nranges, double theta,
	       unsigned int seed)
{
	shared_rand_init(zs, nranges, seed);

	zs->theta = theta;
	zs->zeta2 = pow(1.0, zs->theta) + pow(0.5, zs->theta);

	zipf_load_gen_zeta(zs);
}

unsigned long long zipf_next(struct zipf_state *zs)
{
	double alpha, eta, rand_uni, rand_z;
	unsigned long long n = zs->nranges;
	unsigned long long val;

	alpha = 1.0 / (1.0 - zs->theta);
	eta = (1.0 - pow(2.0 / n, 1.0 - zs->theta)) / (1.0 - zs->zeta2 / zs->zetan);

	rand_uni = (double) __rand(&zs->rand) / (double) FRAND_MAX;
	rand_z = rand_uni * zs->zetan;

	if (rand_z < 1.0)
		val = 1;
	else if (rand_z < (1.0 + pow(0.5, zs->theta)))
		val = 2;
	else
		val = 1 + (unsigned long long)(n * pow(eta*rand_uni - eta + 1.0, alpha));

	return (__hash_long(val - 1) + zs->rand_off) % zs->nranges;
}

void pareto_init(struct zipf_state *zs, unsigned long nranges, double h,
		 unsigned int seed)
{
	shared_rand_init(zs, nranges, seed);
	zs->pareto_pow = log(h) / log(1.0 - h);
}

unsigned long long pareto_next(struct zipf_state *zs)
{
	double rand = (double) __rand(&zs->rand) / (double) FRAND_MAX;
	unsigned long long n = zs->nranges - 1;

	return (__hash_long(n * pow(rand, zs->pareto_pow)) + zs->rand_off) % zs->nranges;
}
