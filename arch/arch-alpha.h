#ifndef ARCH_ALPHA_H
#define ARCH_ALPHA_H

#define ARCH	(arch_alpha)

#ifndef __NR_ioprio_set
#define __NR_ioprio_set		442
#define __NR_ioprio_get		443
#endif

#ifndef __NR_fadvise64
#define __NR_fadvise64		413
#endif

#define nop		do { } while (0)
#define fio_ffz(v)	generic_ffz((v))

#endif
