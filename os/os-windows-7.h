#define FIO_MAX_CPUS		512 /* From Hyper-V 2016's max logical processors */
#define FIO_CPU_MASK_STRIDE	64
#define FIO_CPU_MASK_ROWS	(FIO_MAX_CPUS / FIO_CPU_MASK_STRIDE)

typedef struct {
	uint64_t row[FIO_CPU_MASK_ROWS];
} os_cpu_mask_t;
