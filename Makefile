DEBUGFLAGS = -D_FORTIFY_SOURCE=2 -DFIO_INC_DEBUG
CPPFLAGS= -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
	$(DEBUGFLAGS)
OPTFLAGS= -O3 -g -ffast-math $(EXTFLAGS)
CFLAGS	= -std=gnu99 -Wwrite-strings -Wall $(OPTFLAGS)
LIBS	= -lm $(EXTLIBS)
PROGS	= fio
SCRIPTS = fio_generate_plots
UNAME  := $(shell uname)

ifneq ($(wildcard config-host.mak),)
all:
include config-host.mak
config-host-mak: configure
	@echo $@ is out-of-date, running configure
	@sed -n "/.*Configured with/s/[^:]*: //p" $@ | sh
else
config-host.mak:
	@echo "Running configure for you..."
	@./configure
all:
include config-host.mak
endif

SOURCE := gettime.c fio.c ioengines.c init.c stat.c log.c time.c filesetup.c \
		eta.c verify.c memory.c io_u.c parse.c mutex.c options.c \
		rbtree.c smalloc.c filehash.c profile.c debug.c lib/rand.c \
		lib/num2str.c lib/ieee754.c $(wildcard crc/*.c) engines/cpu.c \
		engines/mmap.c engines/sync.c engines/null.c engines/net.c \
		memalign.c server.c client.c iolog.c backend.c libfio.c flow.c \
		json.c lib/zipf.c lib/axmap.c lib/lfsr.c gettime-thread.c \
		helpers.c

ifdef CONFIG_64BIT
  CFLAGS += -DBITS_PER_LONG=64
endif
ifdef CONFIG_32BIT
  CFLAGS += -DBITS_PER_LONG=32
endif

ifdef CONFIG_LIBAIO
  CFLAGS += -DCONFIG_LIBAIO
  SOURCE += engines/libaio.c
endif
ifdef CONFIG_RDMA
  CFLAGS += -DCONFIG_RDMA
  SOURCE += engines/rdma.c
endif
ifdef CONFIG_POSIXAIO
  CFLAGS += -DCONFIG_POSIXAIO
  SOURCE += engines/posixaio.c
endif
ifdef CONFIG_LINUX_FALLOCATE
  SOURCE += engines/falloc.c
endif
ifdef CONFIG_LINUX_EXT4_MOVE_EXTENT
  SOURCE += engines/e4defrag.c
endif
ifdef CONFIG_LINUX_SPLICE
  CFLAGS += -DCONFIG_LINUX_SPLICE
  SOURCE += engines/splice.c
endif
ifdef CONFIG_GUASI
  CFLAGS += -DCONFIG_GUASI
  SOURCE += engines/guasi.c
endif
ifdef CONFIG_FUSION_AW
  CFLAGS += -DCONFIG_FUSION_AW
  SOURCE += engines/fusion-aw.c
endif
ifdef CONFIG_SOLARISAIO
  CFLAGS += -DCONFIG_SOLARISAIO
  SOURCE += engines/solarisaio.c
endif

ifndef CONFIG_STRSEP
  CFLAGS += -DCONFIG_STRSEP
  SOURCE += lib/strsep.c
endif
ifndef CONFIG_GETOPT_LONG_ONLY
  CFLAGS += -DCONFIG_GETOPT_LONG_ONLY
  SOURCE += lib/getopt_long.c
endif

ifndef CONFIG_INET_ATON
  CFLAGS += -DCONFIG_INET_ATON
  SOURCE += lib/inet_aton.c
endif
ifdef CONFIG_CLOCK_GETTIME
  CFLAGS += -DCONFIG_CLOCK_GETTIME
endif
ifdef CONFIG_POSIXAIO_FSYNC
  CFLAGS += -DCONFIG_POSIXAIO_FSYNC
endif
ifdef CONFIG_FADVISE
  CFLAGS += -DCONFIG_FADVISE
endif
ifdef CONFIG_CLOCK_MONOTONIC
  CFLAGS += -DCONFIG_CLOCK_MONOTONIC
endif
ifdef CONFIG_CLOCK_MONOTONIC_PRECISE
  CFLAGS += -DCONFIG_CLOCK_MONOTONIC_PRECISE
endif
ifdef CONFIG_GETTIMEOFDAY
  CFLAGS += -DCONFIG_GETTIMEOFDAY
endif
ifdef CONFIG_SOCKLEN_T
  CFLAGS += -DCONFIG_SOCKLEN_T
endif
ifdef CONFIG_SFAA
  CFLAGS += -DCONFIG_SFAA
endif
ifdef CONFIG_FDATASYNC
  CFLAGS += -DCONFIG_FDATASYNC
endif
ifdef CONFIG_3ARG_AFFINITY
  CFLAGS += -DCONFIG_3ARG_AFFINITY
endif
ifdef CONFIG_2ARG_AFFINITY
  CFLAGS += -DCONFIG_2ARG_AFFINITY
endif
ifdef CONFIG_SYNC_FILE_RANGE
  CFLAGS += -DCONFIG_SYNC_FILE_RANGE
endif
ifdef CONFIG_LIBNUMA
  CFLAGS += -DCONFIG_LIBNUMA
endif
ifdef CONFIG_TLS_THREAD
  CFLAGS += -DCONFIG_TLS_THREAD
endif

ifeq ($(UNAME), Linux)
  SOURCE += diskutil.c fifo.c blktrace.c cgroup.c trim.c engines/sg.c \
		engines/binject.c profiles/tiobench.c
  LIBS += -lpthread -ldl
  LDFLAGS += -rdynamic
endif
ifeq ($(UNAME), Android)
  SOURCE += diskutil.c fifo.c blktrace.c trim.c profiles/tiobench.c
  LIBS += -ldl
  LDFLAGS += -rdynamic
  CPPFLAGS += -DFIO_NO_HAVE_SHM_H
endif
ifeq ($(UNAME), SunOS)
  LIBS	 += -lpthread -ldl -laio -lrt -lnsl -lsocket
  CPPFLAGS += -D__EXTENSIONS__
endif
ifeq ($(UNAME), FreeBSD)
  LIBS	 += -lpthread -lrt
  LDFLAGS += -rdynamic
endif
ifeq ($(UNAME), NetBSD)
  LIBS	 += -lpthread -lrt
  LDFLAGS += -rdynamic
endif
ifeq ($(UNAME), AIX)
  LIBS	 += -lpthread -ldl -lrt
  CPPFLAGS += -D_LARGE_FILES -D__ppc__
  LDFLAGS += -L/opt/freeware/lib -Wl,-blibpath:/opt/freeware/lib:/usr/lib:/lib -Wl,-bmaxdata:0x80000000
endif
ifeq ($(UNAME), HP-UX)
  LIBS   += -lpthread -ldl -lrt
  CFLAGS += -D_LARGEFILE64_SOURCE -D_XOPEN_SOURCE_EXTENDED
endif
ifeq ($(UNAME), Darwin)
  LIBS	 += -lpthread -ldl
endif
ifneq (,$(findstring CYGWIN,$(UNAME)))
  SOURCE := $(filter-out engines/mmap.c,$(SOURCE))
  SOURCE += engines/windowsaio.c os/windows/posix.c
  LIBS	 += -lpthread -lpsapi -lws2_32
  CFLAGS += -DPSAPI_VERSION=1 -Ios/windows/posix/include -Wno-format
endif

OBJS = $(SOURCE:.c=.o)

T_SMALLOC_OBJS = t/stest.o
T_SMALLOC_OBJS += gettime.o mutex.o smalloc.o t/log.o
T_SMALLOC_PROGS = t/stest

T_IEEE_OBJS = t/ieee754.o
T_IEEE_OBJS += lib/ieee754.o
T_IEEE_PROGS = t/ieee754

T_ZIPF_OBS = t/genzipf.o
T_ZIPF_OBJS += t/log.o lib/ieee754.o lib/rand.o lib/zipf.o t/genzipf.o
T_ZIPF_PROGS = t/genzipf

T_AXMAP_OBJS = t/axmap.o
T_AXMAP_OBJS += lib/lfsr.o lib/axmap.o
T_AXMAP_PROGS = t/axmap

T_OBJS = $(T_SMALLOC_OBJS)
T_OBJS += $(T_IEEE_OBJS)
T_OBJS += $(T_ZIPF_OBJS)
T_OBJS += $(T_AXMAP_OBJS)

T_PROGS = $(T_SMALLOC_PROGS)
T_PROGS += $(T_IEEE_PROGS)
T_PROGS += $(T_ZIPF_PROGS)
T_PROGS += $(T_AXMAP_PROGS)

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '   ' CC $@;
	QUIET_DEP	= @echo '   ' DEP $@;
endif
endif

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin

ifeq ($(UNAME), Darwin)
mandir = /usr/share/man
else
mandir = $(prefix)/man
endif

all: .depend $(PROGS) $(SCRIPTS) FORCE

.PHONY: all install clean
.PHONY: FORCE cscope

FIO-VERSION-FILE: FORCE
	@$(SHELL) ./FIO-VERSION-GEN
-include FIO-VERSION-FILE

CFLAGS += -DFIO_VERSION='"$(FIO_VERSION)"'

.c.o: .depend FORCE
	$(QUIET_CC)$(CC) -o $@ -c $(CFLAGS) $(CPPFLAGS) $<

init.o: FIO-VERSION-FILE
	$(QUIET_CC)$(CC) -o init.o -c $(CFLAGS) $(CPPFLAGS) -c init.c

t/stest: $(T_SMALLOC_OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_SMALLOC_OBJS) $(LIBS) $(LDFLAGS)

t/ieee754: $(T_IEEE_OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_IEEE_OBJS) $(LIBS) $(LDFLAGS)

t/genzipf: $(T_ZIPF_OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_ZIPF_OBJS) $(LIBS) $(LDFLAGS)

t/axmap: $(T_AXMAP_OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_AXMAP_OBJS) $(LIBS) $(LDFLAGS)

fio: $(OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LIBS) $(LDFLAGS)

.depend: $(SOURCE)
	$(QUIET_DEP)$(CC) -MM $(CFLAGS) $(CPPFLAGS) $(SOURCE) 1> .depend

$(PROGS): .depend

clean: FORCE
	-rm -f .depend $(OBJS) $(T_OBJS) $(PROGS) $(T_PROGS) core.* core FIO-VERSION-FILE config-host.mak config-host.ld cscope.out

cscope:
	@cscope -b -R

install: $(PROGS) $(SCRIPTS) FORCE
	$(INSTALL) -m 755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 fio.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 fio_generate_plots.1 $(DESTDIR)$(mandir)/man1

ifneq ($(wildcard .depend),)
include .depend
endif
