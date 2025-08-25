ifeq ($(SRCDIR),)
SRCDIR := .
endif

VPATH := $(SRCDIR)

all: fio

config-host.mak: configure
	@if [ ! -e "$@" ]; then					\
	  echo "Running configure ...";				\
	  ./configure;						\
	else							\
	  echo "$@ is out-of-date, running configure";		\
	  sed -n "/.*Configured with/s/[^:]*: //p" "$@" | sh;	\
	fi

ifneq ($(MAKECMDGOALS),clean)
include config-host.mak
endif

DEBUGFLAGS = -DFIO_INC_DEBUG
CPPFLAGS+= -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DFIO_INTERNAL $(DEBUGFLAGS)
OPTFLAGS= -g -ffast-math
FIO_CFLAGS= -std=gnu99 -Wwrite-strings -Wall -Wdeclaration-after-statement $(OPTFLAGS) $(EXTFLAGS) $(BUILD_CFLAGS) -I. -I$(SRCDIR)
LIBS	+= -lm $(EXTLIBS)
PROGS	= fio
SCRIPTS = $(addprefix $(SRCDIR)/,tools/fio_generate_plots tools/plot/fio2gnuplot tools/genfio tools/fiologparser.py tools/hist/fiologparser_hist.py tools/hist/fio-histo-log-pctiles.py tools/fio_jsonplus_clat2csv)

ifndef CONFIG_FIO_NO_OPT
  FIO_CFLAGS += -O3
endif
ifdef CONFIG_BUILD_NATIVE
  FIO_CFLAGS += -march=native
endif

ifdef CONFIG_PDB
  LINK_PDBFILE ?= -Wl,-pdb,$(dir $@)/$(basename $(@F)).pdb
  FIO_CFLAGS += -gcodeview
  LDFLAGS += -fuse-ld=lld $(LINK_PDBFILE)
endif

# If clang, do not use builtin stpcpy as it breaks the build
ifeq ($(CC),clang)
  FIO_CFLAGS += -fno-builtin-stpcpy
endif

ifdef CONFIG_GFIO
  PROGS += gfio
endif

SOURCE :=	$(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/crc/*.c)) \
		$(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/lib/*.c))) \
		gettime.c ioengines.c init.c stat.c log.c time.c filesetup.c \
		eta.c verify.c memory.c io_u.c parse.c fio_sem.c rwlock.c \
		pshared.c options.c fio_shared_sem.c \
		smalloc.c filehash.c profile.c debug.c engines/cpu.c \
		engines/mmap.c engines/sync.c engines/null.c engines/net.c \
		engines/ftruncate.c engines/fileoperations.c \
		engines/exec.c \
		server.c client.c iolog.c backend.c libfio.c flow.c cconv.c \
		gettime-thread.c helpers.c json.c idletime.c td_error.c \
		profiles/tiobench.c profiles/act.c io_u_queue.c filelock.c \
		workqueue.c rate-submit.c optgroup.c helper_thread.c \
		steadystate.c zone-dist.c zbd.c dedupe.c dataplacement.c \
		sprandom.c

ifdef CONFIG_LIBHDFS
  HDFSFLAGS= -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -I $(FIO_LIBHDFS_INCLUDE)
  HDFSLIB= -Wl,-rpath $(JAVA_HOME)/lib/$(FIO_HDFS_CPU)/server -L$(JAVA_HOME)/lib/$(FIO_HDFS_CPU)/server $(FIO_LIBHDFS_LIB)/libhdfs.a -ljvm
  FIO_CFLAGS += $(HDFSFLAGS)
  SOURCE += engines/libhdfs.c
endif

ifdef CONFIG_LIBISCSI
  libiscsi_SRCS = engines/libiscsi.c
  libiscsi_LIBS = $(LIBISCSI_LIBS)
  libiscsi_CFLAGS = $(LIBISCSI_CFLAGS)
  ENGINES += libiscsi
endif

ifdef CONFIG_LIBNBD
  nbd_SRCS = engines/nbd.c
  nbd_LIBS = $(LIBNBD_LIBS)
  nbd_CFLAGS = $(LIBNBD_CFLAGS)
  ENGINES += nbd
endif

ifdef CONFIG_LIBNFS
  CFLAGS += $(LIBNFS_CFLAGS)
  LIBS += $(LIBNFS_LIBS)
  SOURCE += engines/nfs.c
endif

ifdef CONFIG_64BIT
  CPPFLAGS += -DBITS_PER_LONG=64
else ifdef CONFIG_32BIT
  CPPFLAGS += -DBITS_PER_LONG=32
endif
ifdef CONFIG_LIBAIO
  libaio_SRCS = engines/libaio.c
  cmdprio_SRCS = engines/cmdprio.c
  LIBS += -laio
  libaio_LIBS = -laio
  ENGINES += libaio
endif
ifdef CONFIG_RDMA
  rdma_SRCS = engines/rdma.c
  rdma_LIBS = -libverbs -lrdmacm
  ENGINES += rdma
endif
ifdef CONFIG_POSIXAIO
  SOURCE += engines/posixaio.c
endif
ifdef CONFIG_LINUX_FALLOCATE
  SOURCE += engines/falloc.c
endif
ifdef CONFIG_LINUX_EXT4_MOVE_EXTENT
  SOURCE += engines/e4defrag.c
endif
ifdef CONFIG_LIBCUFILE
  SOURCE += engines/libcufile.c
endif
ifdef CONFIG_LINUX_SPLICE
  SOURCE += engines/splice.c
endif
ifdef CONFIG_SOLARISAIO
  SOURCE += engines/solarisaio.c
endif
ifdef CONFIG_WINDOWSAIO
  SOURCE += engines/windowsaio.c
endif
ifdef CONFIG_RADOS
  rados_SRCS = engines/rados.c
  rados_LIBS = -lrados
  ENGINES += rados
endif
ifdef CONFIG_RBD
  rbd_SRCS = engines/rbd.c
  rbd_LIBS = -lrbd -lrados
  ENGINES += rbd
endif
ifdef CONFIG_HTTP
  http_SRCS = engines/http.c
  http_LIBS = -lcurl -lssl -lcrypto
  ENGINES += http
endif
ifdef CONFIG_DFS
  dfs_SRCS = engines/dfs.c
  dfs_LIBS = -luuid -ldaos -ldfs
  ENGINES += dfs
endif
SOURCE += oslib/asprintf.c
ifndef CONFIG_STRSEP
  SOURCE += oslib/strsep.c
endif
ifndef CONFIG_STRCASESTR
  SOURCE += oslib/strcasestr.c
endif
ifndef CONFIG_STRLCAT
  SOURCE += oslib/strlcat.c
endif
ifndef CONFIG_HAVE_STRNDUP
  SOURCE += oslib/strndup.c
endif
ifndef CONFIG_GETOPT_LONG_ONLY
  SOURCE += oslib/getopt_long.c
endif
ifndef CONFIG_INET_ATON
  SOURCE += oslib/inet_aton.c
endif
ifndef CONFIG_HAVE_STATX
  SOURCE += oslib/statx.c
endif
ifdef CONFIG_GFAPI
  SOURCE += engines/glusterfs.c
  SOURCE += engines/glusterfs_sync.c
  SOURCE += engines/glusterfs_async.c
  LIBS += -lgfapi -lglusterfs
  ifdef CONFIG_GF_FADVISE
    FIO_CFLAGS += "-DGFAPI_USE_FADVISE"
  endif
endif
ifdef CONFIG_MTD
  SOURCE += engines/mtd.c
  SOURCE += oslib/libmtd.c
  SOURCE += oslib/libmtd_legacy.c
endif
ifdef CONFIG_LINUX_DEVDAX
  dev-dax_SRCS = engines/dev-dax.c
  dev-dax_LIBS = -lpmem
  ENGINES += dev-dax
endif
ifdef CONFIG_LIBPMEM
  libpmem_SRCS = engines/libpmem.c
  libpmem_LIBS = -lpmem
  ENGINES += libpmem
endif
ifdef CONFIG_IME
  SOURCE += engines/ime.c
endif
ifdef CONFIG_LIBZBC
  libzbc_SRCS = engines/libzbc.c
  libzbc_LIBS = -lzbc
  ENGINES += libzbc
endif
ifdef CONFIG_LIBXNVME
  xnvme_SRCS = engines/xnvme.c
  xnvme_LIBS = $(LIBXNVME_LIBS)
  xnvme_CFLAGS = $(LIBXNVME_CFLAGS)
  ENGINES += xnvme
endif
ifdef CONFIG_LIBBLKIO
  libblkio_SRCS = engines/libblkio.c
  libblkio_LIBS = $(LIBBLKIO_LIBS)
  libblkio_CFLAGS = $(LIBBLKIO_CFLAGS)
  ENGINES += libblkio
endif
ifeq ($(CONFIG_TARGET_OS), Linux)
  SOURCE += diskutil.c fifo.c blktrace.c cgroup.c trim.c engines/sg.c \
		oslib/linux-dev-lookup.c engines/io_uring.c engines/nvme.c
  cmdprio_SRCS = engines/cmdprio.c
ifdef CONFIG_HAS_BLKZONED
  SOURCE += oslib/linux-blkzoned.c
endif
  LIBS += -lpthread -ldl
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), Android)
  SOURCE += diskutil.c fifo.c blktrace.c cgroup.c trim.c profiles/tiobench.c \
		oslib/linux-dev-lookup.c engines/io_uring.c engines/nvme.c \
		engines/sg.c
  cmdprio_SRCS = engines/cmdprio.c
ifdef CONFIG_HAS_BLKZONED
  SOURCE += oslib/linux-blkzoned.c
endif
  LIBS += -ldl -llog
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), SunOS)
  LIBS	 += -lpthread -ldl
  CPPFLAGS += -D__EXTENSIONS__
endif
ifeq ($(CONFIG_TARGET_OS), FreeBSD)
  SOURCE += trim.c
  LIBS	 += -lpthread -lrt
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), OpenBSD)
  LIBS	 += -lpthread
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), NetBSD)
  LIBS	 += -lpthread -lrt
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), DragonFly)
  SOURCE += trim.c
  LIBS	 += -lpthread -lrt
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), AIX)
  LIBS	 += -lpthread -ldl -lrt
  CPPFLAGS += -D_LARGE_FILES -D__ppc__
  LDFLAGS += -L/opt/freeware/lib -Wl,-blibpath:/opt/freeware/lib:/usr/lib:/lib -Wl,-bmaxdata:0x80000000
endif
ifeq ($(CONFIG_TARGET_OS), HP-UX)
  LIBS   += -lpthread -ldl -lrt
  FIO_CFLAGS += -D_LARGEFILE64_SOURCE -D_XOPEN_SOURCE_EXTENDED
endif
ifeq ($(CONFIG_TARGET_OS), Darwin)
  LIBS	 += -lpthread -ldl
endif
ifneq (,$(findstring CYGWIN,$(CONFIG_TARGET_OS)))
  SOURCE += os/windows/cpu-affinity.c os/windows/posix.c os/windows/dlls.c
  WINDOWS_OBJS = os/windows/cpu-affinity.o os/windows/posix.o os/windows/dlls.o lib/hweight.o
  LIBS	 += -lpthread -lpsapi -lws2_32 -lssp
  FIO_CFLAGS += -DPSAPI_VERSION=1 -Ios/windows/posix/include -Wno-format
endif

ifdef cmdprio_SRCS
  SOURCE += $(cmdprio_SRCS)
endif

ifdef CONFIG_DYNAMIC_ENGINES
 DYNAMIC_ENGS := $(ENGINES)
define engine_template =
$(1)_OBJS := $$($(1)_SRCS:.c=.o)
$$($(1)_OBJS): CFLAGS := -fPIC $$($(1)_CFLAGS) $(CFLAGS)
engines/fio-$(1).so: $$($(1)_OBJS)
	$$(QUIET_LINK)$(CC) $(LDFLAGS) -shared -rdynamic -fPIC -Wl,-soname,fio-$(1).so.1 -o $$@ $$< $$($(1)_LIBS)
ENGS_OBJS += engines/fio-$(1).so
endef
else # !CONFIG_DYNAMIC_ENGINES
define engine_template =
SOURCE += $$($(1)_SRCS)
LIBS += $$($(1)_LIBS)
override CFLAGS += $$($(1)_CFLAGS)
endef
endif

FIO-VERSION-FILE: FORCE
	@$(SHELL) $(SRCDIR)/FIO-VERSION-GEN
-include FIO-VERSION-FILE

override CFLAGS := -DFIO_VERSION='"$(FIO_VERSION)"' $(FIO_CFLAGS) $(CFLAGS)

$(foreach eng,$(ENGINES),$(eval $(call engine_template,$(eng))))

OBJS := $(SOURCE:.c=.o)

FIO_OBJS = $(OBJS) fio.o

GFIO_OBJS = $(OBJS) gfio.o graph.o tickmarks.o ghelpers.o goptions.o gerror.o \
			gclient.o gcompat.o cairo_text_helpers.o printing.o

ifdef CONFIG_ARITHMETIC
FIO_OBJS += lex.yy.o y.tab.o
GFIO_OBJS += lex.yy.o y.tab.o
endif

-include $(OBJS:.o=.d) $(T_OBJS:.o=.d) $(UT_OBJS:.o=.d)

T_SMALLOC_OBJS = t/stest.o
T_SMALLOC_OBJS += gettime.o fio_sem.o pshared.o smalloc.o t/log.o t/debug.o \
		  t/arch.o
T_SMALLOC_PROGS = t/stest

T_IEEE_OBJS = t/ieee754.o
T_IEEE_OBJS += lib/ieee754.o
T_IEEE_PROGS = t/ieee754

T_ZIPF_OBS = t/genzipf.o
T_ZIPF_OBJS += t/log.o lib/ieee754.o lib/rand.o lib/pattern.o lib/zipf.o \
		lib/strntol.o lib/gauss.o t/genzipf.o oslib/strcasestr.o \
		oslib/strndup.o
T_ZIPF_PROGS = t/fio-genzipf

T_AXMAP_OBJS = t/axmap.o
T_AXMAP_OBJS += lib/lfsr.o lib/axmap.o
T_AXMAP_PROGS = t/axmap

T_LFSR_TEST_OBJS = t/lfsr-test.o
T_LFSR_TEST_OBJS += lib/lfsr.o gettime.o fio_sem.o pshared.o \
		    t/log.o t/debug.o t/arch.o
T_LFSR_TEST_PROGS = t/lfsr-test

T_GEN_RAND_OBJS = t/gen-rand.o
T_GEN_RAND_OBJS += t/log.o t/debug.o lib/rand.o lib/pattern.o lib/strntol.o \
			oslib/strcasestr.o oslib/strndup.o
T_GEN_RAND_PROGS = t/gen-rand

ifeq ($(CONFIG_TARGET_OS), Linux)
T_BTRACE_FIO_OBJS = t/btrace2fio.o
T_BTRACE_FIO_OBJS += fifo.o lib/flist_sort.o t/log.o oslib/linux-dev-lookup.o
T_BTRACE_FIO_PROGS = t/fio-btrace2fio
endif

T_DEDUPE_OBJS = t/dedupe.o
T_DEDUPE_OBJS += lib/rbtree.o t/log.o fio_sem.o pshared.o smalloc.o gettime.o \
		crc/md5.o lib/memalign.o lib/bloom.o t/debug.o crc/xxhash.o \
		t/arch.o crc/murmur3.o crc/crc32c.o crc/crc32c-intel.o \
		crc/crc32c-arm64.o crc/fnv.o
T_DEDUPE_PROGS = t/fio-dedupe

T_VS_OBJS = t/verify-state.o t/log.o crc/crc32c.o crc/crc32c-intel.o crc/crc32c-arm64.o t/debug.o
T_VS_PROGS = t/fio-verify-state

T_PIPE_ASYNC_OBJS = t/read-to-pipe-async.o t/log.o
T_PIPE_ASYNC_PROGS = t/read-to-pipe-async

T_IOU_RING_OBJS = t/io_uring.o lib/rand.o lib/pattern.o lib/strntol.o
T_IOU_RING_PROGS = t/io_uring

T_MEMLOCK_OBJS = t/memlock.o
T_MEMLOCK_PROGS = t/memlock

T_TT_OBJS = t/time-test.o
T_TT_PROGS = t/time-test

ifneq (,$(findstring -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION,$(CFLAGS)))
T_FUZZ_OBJS = t/fuzz/fuzz_parseini.o
T_FUZZ_OBJS += $(OBJS)
ifdef CONFIG_ARITHMETIC
T_FUZZ_OBJS += lex.yy.o y.tab.o
endif
# For proper fio code teardown CFLAGS needs to include -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
# in case there is no fuzz driver defined by environment variable LIB_FUZZING_ENGINE, use a simple one
# For instance, with compiler clang, address sanitizer and libFuzzer as a fuzzing engine, you should define
# export CFLAGS="-fsanitize=address,fuzzer-no-link -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION"
# export LIB_FUZZING_ENGINE="-fsanitize=address"
# export CC=clang
# before running configure && make
# You can adapt this with different compilers, sanitizers, and fuzzing engines
ifndef LIB_FUZZING_ENGINE
T_FUZZ_OBJS += t/fuzz/onefile.o
endif
T_FUZZ_PROGS = t/fuzz/fuzz_parseini
else	# CFLAGS includes -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
T_FUZZ_OBJS =
T_FUZZ_PROGS =
endif

T_OBJS = $(T_SMALLOC_OBJS)
T_OBJS += $(T_IEEE_OBJS)
T_OBJS += $(T_ZIPF_OBJS)
T_OBJS += $(T_AXMAP_OBJS)
T_OBJS += $(T_LFSR_TEST_OBJS)
T_OBJS += $(T_GEN_RAND_OBJS)
T_OBJS += $(T_BTRACE_FIO_OBJS)
T_OBJS += $(T_DEDUPE_OBJS)
T_OBJS += $(T_VS_OBJS)
T_OBJS += $(T_PIPE_ASYNC_OBJS)
T_OBJS += $(T_MEMLOCK_OBJS)
T_OBJS += $(T_TT_OBJS)
T_OBJS += $(T_IOU_RING_OBJS)
T_OBJS += $(T_FUZZ_OBJS)

ifneq (,$(findstring CYGWIN,$(CONFIG_TARGET_OS)))
    T_DEDUPE_OBJS += $(WINDOWS_OBJS)
    T_SMALLOC_OBJS += $(WINDOWS_OBJS)
    T_LFSR_TEST_OBJS += $(WINDOWS_OBJS)
endif

T_TEST_PROGS = $(T_SMALLOC_PROGS)
T_TEST_PROGS += $(T_IEEE_PROGS)
T_PROGS += $(T_ZIPF_PROGS)
T_TEST_PROGS += $(T_AXMAP_PROGS)
T_TEST_PROGS += $(T_LFSR_TEST_PROGS)
T_TEST_PROGS += $(T_GEN_RAND_PROGS)
T_PROGS += $(T_BTRACE_FIO_PROGS)
ifdef CONFIG_ZLIB
T_PROGS += $(T_DEDUPE_PROGS)
endif
T_PROGS += $(T_VS_PROGS)
T_TEST_PROGS += $(T_MEMLOCK_PROGS)
ifdef CONFIG_PREAD
T_TEST_PROGS += $(T_PIPE_ASYNC_PROGS)
endif
ifneq (,$(findstring Linux,$(CONFIG_TARGET_OS)))
T_TEST_PROGS += $(T_IOU_RING_PROGS)
endif
T_TEST_PROGS += $(T_FUZZ_PROGS)

PROGS += $(T_PROGS)

ifdef CONFIG_HAVE_CUNIT
UT_OBJS = unittests/unittest.o
UT_OBJS += unittests/lib/memalign.o
UT_OBJS += unittests/lib/num2str.o
UT_OBJS += unittests/lib/strntol.o
UT_OBJS += unittests/lib/pcbuf.o
UT_OBJS += unittests/oslib/strlcat.o
UT_OBJS += unittests/oslib/strndup.o
UT_OBJS += unittests/oslib/strcasestr.o
UT_OBJS += unittests/oslib/strsep.o
UT_TARGET_OBJS = lib/memalign.o
UT_TARGET_OBJS += lib/num2str.o
UT_TARGET_OBJS += lib/strntol.o
UT_TARGET_OBJS += oslib/strlcat.o
UT_TARGET_OBJS += oslib/strndup.o
UT_TARGET_OBJS += oslib/strcasestr.o
UT_TARGET_OBJS += oslib/strsep.o
UT_PROGS = unittests/unittest
else
UT_OBJS =
UT_TARGET_OBJS =
UT_PROGS =
endif

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '   ' CC $@;
	QUIET_LINK	= @echo ' ' LINK $@;
	QUIET_DEP	= @echo '  ' DEP $@;
	QUIET_YACC	= @echo ' ' YACC $@;
	QUIET_LEX	= @echo '  ' LEX $@;
endif
endif

ifeq ($(CONFIG_TARGET_OS), SunOS)
	INSTALL = ginstall
else
	INSTALL = install
endif
prefix = $(INSTALL_PREFIX)
bindir = $(prefix)/bin
libdir = $(prefix)/lib/fio
mandir = $(prefix)/share/man
sharedir = $(prefix)/share/fio

all: $(PROGS) $(T_TEST_PROGS) $(UT_PROGS) $(SCRIPTS) $(ENGS_OBJS) FORCE

.PHONY: all install clean test
.PHONY: FORCE cscope

%.o : %.c
	@mkdir -p $(dir $@)
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<
	@$(CC) -MM $(CFLAGS) $(CPPFLAGS) $(SRCDIR)/$*.c > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@if type -p fmt >/dev/null 2>&1; then				\
		sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -w 1 |	\
		sed -e 's/^ *//' -e 's/$$/:/' >> $*.d;			\
	else								\
		sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp |		\
		tr -cs "[:graph:]" "\n" |				\
		sed -e 's/^ *//' -e '/^$$/ d' -e 's/$$/:/' >> $*.d;	\
	fi
	@rm -f $*.d.tmp

ifdef CONFIG_ARITHMETIC
lex.yy.c: exp/expression-parser.l
ifdef CONFIG_LEX_USE_O
	$(QUIET_LEX)$(LEX) -o $@ $<
else
	$(QUIET_LEX)$(LEX) $<
endif

ifneq (,$(findstring -Wimplicit-fallthrough,$(CFLAGS)))
LEX_YY_CFLAGS := -Wno-implicit-fallthrough
endif

ifdef CONFIG_HAVE_NO_STRINGOP
YTAB_YY_CFLAGS := -Wno-stringop-truncation
endif

lex.yy.o: lex.yy.c y.tab.h
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) $(LEX_YY_CFLAGS) -c $<

y.tab.o: y.tab.c y.tab.h
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) $(YTAB_YY_CFLAGS) -c $<

y.tab.c: exp/expression-parser.y
	$(QUIET_YACC)$(YACC) -o $@ -l -d -b y $<

y.tab.h: y.tab.c

lexer.h: lex.yy.c

exp/test-expression-parser.o: exp/test-expression-parser.c
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<
exp/test-expression-parser: exp/test-expression-parser.o
	$(QUIET_LINK)$(CC) $(LDFLAGS) $< y.tab.o lex.yy.o -o $@ $(LIBS)

parse.o: lex.yy.o y.tab.o
endif

init.o: init.c FIO-VERSION-FILE

gcompat.o: gcompat.c gcompat.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

goptions.o: goptions.c goptions.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

ghelpers.o: ghelpers.c ghelpers.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

gerror.o: gerror.c gerror.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

gclient.o: gclient.c gclient.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

gfio.o: gfio.c ghelpers.c
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

graph.o: graph.c graph.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

cairo_text_helpers.o: cairo_text_helpers.c cairo_text_helpers.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

printing.o: printing.c printing.h
	$(QUIET_CC)$(CC) $(CFLAGS) $(GTK_CFLAGS) $(CPPFLAGS) -c $<

t/io_uring.o: os/linux/io_uring.h
t/io_uring: $(T_IOU_RING_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_IOU_RING_OBJS) $(LIBS)

t/read-to-pipe-async: $(T_PIPE_ASYNC_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_PIPE_ASYNC_OBJS) $(LIBS)

t/memlock: $(T_MEMLOCK_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_MEMLOCK_OBJS) $(LIBS)

t/stest: $(T_SMALLOC_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_SMALLOC_OBJS) $(LIBS)

t/ieee754: $(T_IEEE_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_IEEE_OBJS) $(LIBS)

fio: $(FIO_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(FIO_OBJS) $(LIBS) $(HDFSLIB)

t/fuzz/fuzz_parseini: $(T_FUZZ_OBJS)
ifndef LIB_FUZZING_ENGINE
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_FUZZ_OBJS) $(LIBS) $(HDFSLIB)
else
	$(QUIET_LINK)$(CXX) $(LDFLAGS) -o $@ $(T_FUZZ_OBJS) $(LIB_FUZZING_ENGINE) $(LIBS) $(HDFSLIB)
endif

gfio: $(GFIO_OBJS)
	$(QUIET_LINK)$(CC) $(filter-out -static, $(LDFLAGS)) -o gfio $(GFIO_OBJS) $(LIBS) $(GFIO_LIBS) $(GTK_LDFLAGS) $(HDFSLIB)

t/fio-genzipf: $(T_ZIPF_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_ZIPF_OBJS) $(LIBS)

t/axmap: $(T_AXMAP_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_AXMAP_OBJS) $(LIBS)

t/lfsr-test: $(T_LFSR_TEST_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_LFSR_TEST_OBJS) $(LIBS)

t/gen-rand: $(T_GEN_RAND_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_GEN_RAND_OBJS) $(LIBS)

ifeq ($(CONFIG_TARGET_OS), Linux)
t/fio-btrace2fio: $(T_BTRACE_FIO_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_BTRACE_FIO_OBJS) $(LIBS)
endif

ifdef CONFIG_ZLIB
t/fio-dedupe: $(T_DEDUPE_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_DEDUPE_OBJS) $(LIBS)
endif

t/fio-verify-state: $(T_VS_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_VS_OBJS) $(LIBS)

t/time-test: $(T_TT_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(T_TT_OBJS) $(LIBS)

ifdef CONFIG_HAVE_CUNIT
unittests/unittest: $(UT_OBJS) $(UT_TARGET_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) -o $@ $(UT_OBJS) $(UT_TARGET_OBJS) -lcunit $(LIBS)
endif

clean: FORCE
	@rm -f .depend $(FIO_OBJS) $(GFIO_OBJS) $(OBJS) $(T_OBJS) $(UT_OBJS) $(PROGS) $(T_PROGS) $(T_TEST_PROGS) core.* core gfio unittests/unittest FIO-VERSION-FILE *.[do] lib/*.d oslib/*.[do] crc/*.d engines/*.[do] engines/*.so profiles/*.[do] t/*.[do] t/*/*.[do] unittests/*.[do] unittests/*/*.[do] config-host.mak config-host.h y.tab.[ch] lex.yy.c exp/*.[do] lexer.h
	@rm -f t/fio-btrace2fio t/io_uring t/read-to-pipe-async
	@rm -rf  doc/output

distclean: clean FORCE
	@rm -f cscope.out fio.pdf fio_generate_plots.pdf fio2gnuplot.pdf fiologparser_hist.pdf

cscope:
	@cscope -b -R

tools/plot/fio2gnuplot.1:
	@cat tools/plot/fio2gnuplot.manpage | txt2man -t fio2gnuplot >  tools/plot/fio2gnuplot.1

doc: tools/plot/fio2gnuplot.1
	@man -t ./fio.1 | ps2pdf - fio.pdf
	@man -t tools/fio_generate_plots.1 | ps2pdf - fio_generate_plots.pdf
	@man -t tools/plot/fio2gnuplot.1 | ps2pdf - fio2gnuplot.pdf
	@man -t tools/hist/fiologparser_hist.py.1 | ps2pdf - fiologparser_hist.pdf

test: fio
	./fio --minimal --thread --exitall_on_error --runtime=1s --name=nulltest --ioengine=null --rw=randrw --iodepth=2 --norandommap --random_generator=tausworthe64 --size=16T --name=verifyfstest --filename=fiotestfile.tmp --unlink=1 --rw=write --verify=crc32c --verify_state_save=0 --size=16K

fulltest:
	sudo modprobe null_blk &&				 	\
	if [ ! -e /usr/include/libzbc/zbc.h ]; then			\
	  git clone https://github.com/westerndigitalcorporation/libzbc && \
	  (cd libzbc &&						 	\
	   ./autogen.sh &&					 	\
	   ./configure --prefix=/usr &&				 	\
	   make -j &&						 	\
	   sudo make install)						\
	fi &&					 			\
	sudo t/zbd/run-tests-against-nullb -s 1 &&		 	\
	if [ -e /sys/module/null_blk/parameters/zoned ]; then		\
		sudo t/zbd/run-tests-against-nullb -s 2;	 	\
		sudo t/zbd/run-tests-against-nullb -s 4;	 	\
	fi

install: $(PROGS) $(SCRIPTS) $(ENGS_OBJS) tools/plot/fio2gnuplot.1 FORCE
	$(INSTALL) -m 755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)
ifdef CONFIG_DYNAMIC_ENGINES
	$(INSTALL) -m 755 -d $(DESTDIR)$(libdir)
	$(INSTALL) -m 755 $(SRCDIR)/engines/*.so $(DESTDIR)$(libdir)
endif
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/fio.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/fio_generate_plots.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/plot/fio2gnuplot.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/hist/fiologparser_hist.py.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 755 -d $(DESTDIR)$(sharedir)
	$(INSTALL) -m 644 $(SRCDIR)/tools/plot/*gpm $(DESTDIR)$(sharedir)/

.PHONY: test fulltest
