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
CPPFLAGS= -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -DFIO_INTERNAL $(DEBUGFLAGS)
OPTFLAGS= -g -ffast-math
CFLAGS	= -std=gnu99 -Wwrite-strings -Wall -Wdeclaration-after-statement $(OPTFLAGS) $(EXTFLAGS) $(BUILD_CFLAGS) -I. -I$(SRCDIR)
LIBS	+= -lm $(EXTLIBS)
PROGS	= fio
SCRIPTS = $(addprefix $(SRCDIR)/,tools/fio_generate_plots tools/plot/fio2gnuplot tools/genfio tools/fiologparser.py tools/hist/fiologparser_hist.py tools/fio_jsonplus_clat2csv)

ifndef CONFIG_FIO_NO_OPT
  CFLAGS += -O3 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
endif
ifdef CONFIG_BUILD_NATIVE
  CFLAGS += -march=native
endif

ifdef CONFIG_GFIO
  PROGS += gfio
endif

SOURCE :=	$(sort $(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/crc/*.c)) \
		$(patsubst $(SRCDIR)/%,%,$(wildcard $(SRCDIR)/lib/*.c))) \
		gettime.c ioengines.c init.c stat.c log.c time.c filesetup.c \
		eta.c verify.c memory.c io_u.c parse.c fio_sem.c rwlock.c \
		pshared.c options.c \
		smalloc.c filehash.c profile.c debug.c engines/cpu.c \
		engines/mmap.c engines/sync.c engines/null.c engines/net.c \
		engines/ftruncate.c engines/filecreate.c engines/filestat.c \
		server.c client.c iolog.c backend.c libfio.c flow.c cconv.c \
		gettime-thread.c helpers.c json.c idletime.c td_error.c \
		profiles/tiobench.c profiles/act.c io_u_queue.c filelock.c \
		workqueue.c rate-submit.c optgroup.c helper_thread.c \
		steadystate.c zone-dist.c

ifdef CONFIG_LIBHDFS
  HDFSFLAGS= -I $(JAVA_HOME)/include -I $(JAVA_HOME)/include/linux -I $(FIO_LIBHDFS_INCLUDE)
  HDFSLIB= -Wl,-rpath $(JAVA_HOME)/jre/lib/$(FIO_HDFS_CPU)/server -L$(JAVA_HOME)/jre/lib/$(FIO_HDFS_CPU)/server $(FIO_LIBHDFS_LIB)/libhdfs.a -ljvm
  CFLAGS += $(HDFSFLAGS)
  SOURCE += engines/libhdfs.c
endif

ifdef CONFIG_LIBISCSI
  CFLAGS += $(LIBISCSI_CFLAGS)
  LIBS += $(LIBISCSI_LIBS)
  SOURCE += engines/libiscsi.c
endif

ifdef CONFIG_LIBNBD
  CFLAGS += $(LIBNBD_CFLAGS)
  LIBS += $(LIBNBD_LIBS)
  SOURCE += engines/nbd.c
endif

ifdef CONFIG_64BIT
  CFLAGS += -DBITS_PER_LONG=64
endif
ifdef CONFIG_32BIT
  CFLAGS += -DBITS_PER_LONG=32
endif
ifdef CONFIG_LIBAIO
  SOURCE += engines/libaio.c
endif
ifdef CONFIG_RDMA
  SOURCE += engines/rdma.c
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
ifdef CONFIG_LINUX_SPLICE
  SOURCE += engines/splice.c
endif
ifdef CONFIG_GUASI
  SOURCE += engines/guasi.c
endif
ifdef CONFIG_SOLARISAIO
  SOURCE += engines/solarisaio.c
endif
ifdef CONFIG_WINDOWSAIO
  SOURCE += engines/windowsaio.c
endif
ifdef CONFIG_RADOS
  SOURCE += engines/rados.c
endif
ifdef CONFIG_RBD
  SOURCE += engines/rbd.c
endif
ifdef CONFIG_HTTP
  SOURCE += engines/http.c
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
ifdef CONFIG_GFAPI
  SOURCE += engines/glusterfs.c
  SOURCE += engines/glusterfs_sync.c
  SOURCE += engines/glusterfs_async.c
  ifdef CONFIG_GF_FADVISE
    CFLAGS += "-DGFAPI_USE_FADVISE"
  endif
endif
ifdef CONFIG_MTD
  SOURCE += engines/mtd.c
  SOURCE += oslib/libmtd.c
  SOURCE += oslib/libmtd_legacy.c
endif
ifdef CONFIG_PMEMBLK
  SOURCE += engines/pmemblk.c
endif
ifdef CONFIG_LINUX_DEVDAX
  SOURCE += engines/dev-dax.c
endif
ifdef CONFIG_LIBPMEM
  SOURCE += engines/libpmem.c
endif
ifdef CONFIG_IME
  SOURCE += engines/ime.c
endif
ifdef CONFIG_LINUX_BLKZONED
  SOURCE += zbd.c
endif

ifeq ($(CONFIG_TARGET_OS), Linux)
  SOURCE += diskutil.c fifo.c blktrace.c cgroup.c trim.c engines/sg.c \
		oslib/linux-dev-lookup.c engines/io_uring.c
  LIBS += -lpthread -ldl
  LDFLAGS += -rdynamic
endif
ifeq ($(CONFIG_TARGET_OS), Android)
  SOURCE += diskutil.c fifo.c blktrace.c cgroup.c trim.c profiles/tiobench.c \
		oslib/linux-dev-lookup.c
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
  CFLAGS += -D_LARGEFILE64_SOURCE -D_XOPEN_SOURCE_EXTENDED
endif
ifeq ($(CONFIG_TARGET_OS), Darwin)
  LIBS	 += -lpthread -ldl
endif
ifneq (,$(findstring CYGWIN,$(CONFIG_TARGET_OS)))
  SOURCE += os/windows/cpu-affinity.c os/windows/posix.c
  WINDOWS_OBJS = os/windows/cpu-affinity.o os/windows/posix.o lib/hweight.o
  LIBS	 += -lpthread -lpsapi -lws2_32 -lssp
  CFLAGS += -DPSAPI_VERSION=1 -Ios/windows/posix/include -Wno-format
endif

OBJS := $(SOURCE:.c=.o)

FIO_OBJS = $(OBJS) fio.o

GFIO_OBJS = $(OBJS) gfio.o graph.o tickmarks.o ghelpers.o goptions.o gerror.o \
			gclient.o gcompat.o cairo_text_helpers.o printing.o

ifdef CONFIG_ARITHMETIC
FIO_OBJS += lex.yy.o y.tab.o
GFIO_OBJS += lex.yy.o y.tab.o
endif

-include $(OBJS:.o=.d)

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

T_PIPE_ASYNC_OBJS = t/read-to-pipe-async.o
T_PIPE_ASYNC_PROGS = t/read-to-pipe-async

T_IOU_RING_OBJS = t/io_uring.o
T_IOU_RING_PROGS = t/io_uring

T_MEMLOCK_OBJS = t/memlock.o
T_MEMLOCK_PROGS = t/memlock

T_TT_OBJS = t/time-test.o
T_TT_PROGS = t/time-test

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
T_PROGS += $(T_DEDUPE_PROGS)
T_PROGS += $(T_VS_PROGS)
T_TEST_PROGS += $(T_MEMLOCK_PROGS)
ifdef CONFIG_PREAD
T_TEST_PROGS += $(T_PIPE_ASYNC_PROGS)
endif
ifneq (,$(findstring Linux,$(CONFIG_TARGET_OS)))
T_TEST_PROGS += $(T_IOU_RING_PROGS)
endif

PROGS += $(T_PROGS)

ifdef CONFIG_HAVE_CUNIT
UT_OBJS = unittests/unittest.o
UT_OBJS += unittests/lib/memalign.o
UT_OBJS += unittests/lib/strntol.o
UT_OBJS += unittests/oslib/strlcat.o
UT_OBJS += unittests/oslib/strndup.o
UT_OBJS += unittests/oslib/strcasestr.o
UT_OBJS += unittests/oslib/strsep.o
UT_TARGET_OBJS = lib/memalign.o
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

ifeq ($(CONFIG_TARGET_OS), Darwin)
mandir = /usr/share/man
sharedir = /usr/share/fio
else
mandir = $(prefix)/man
sharedir = $(prefix)/share/fio
endif

all: $(PROGS) $(T_TEST_PROGS) $(UT_PROGS) $(SCRIPTS) FORCE

.PHONY: all install clean test
.PHONY: FORCE cscope

FIO-VERSION-FILE: FORCE
	@$(SHELL) $(SRCDIR)/FIO-VERSION-GEN
-include FIO-VERSION-FILE

override CFLAGS += -DFIO_VERSION='"$(FIO_VERSION)"'

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

lex.yy.o: lex.yy.c y.tab.h
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<

y.tab.o: y.tab.c y.tab.h
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<

y.tab.c: exp/expression-parser.y
	$(QUIET_YACC)$(YACC) -o $@ -l -d -b y $<

y.tab.h: y.tab.c

lexer.h: lex.yy.c

exp/test-expression-parser.o: exp/test-expression-parser.c
	$(QUIET_CC)$(CC) -o $@ $(CFLAGS) $(CPPFLAGS) -c $<
exp/test-expression-parser: exp/test-expression-parser.o
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) $< y.tab.o lex.yy.o -o $@ $(LIBS)

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
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_IOU_RING_OBJS) $(LIBS)

t/read-to-pipe-async: $(T_PIPE_ASYNC_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_PIPE_ASYNC_OBJS) $(LIBS)

t/memlock: $(T_MEMLOCK_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_MEMLOCK_OBJS) $(LIBS)

t/stest: $(T_SMALLOC_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_SMALLOC_OBJS) $(LIBS)

t/ieee754: $(T_IEEE_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_IEEE_OBJS) $(LIBS)

fio: $(FIO_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(FIO_OBJS) $(LIBS) $(HDFSLIB)

gfio: $(GFIO_OBJS)
	$(QUIET_LINK)$(CC) $(filter-out -static, $(LDFLAGS)) -o gfio $(GFIO_OBJS) $(LIBS) $(GFIO_LIBS) $(GTK_LDFLAGS) $(HDFSLIB)

t/fio-genzipf: $(T_ZIPF_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_ZIPF_OBJS) $(LIBS)

t/axmap: $(T_AXMAP_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_AXMAP_OBJS) $(LIBS)

t/lfsr-test: $(T_LFSR_TEST_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_LFSR_TEST_OBJS) $(LIBS)

t/gen-rand: $(T_GEN_RAND_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_GEN_RAND_OBJS) $(LIBS)

ifeq ($(CONFIG_TARGET_OS), Linux)
t/fio-btrace2fio: $(T_BTRACE_FIO_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_BTRACE_FIO_OBJS) $(LIBS)
endif

t/fio-dedupe: $(T_DEDUPE_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_DEDUPE_OBJS) $(LIBS)

t/fio-verify-state: $(T_VS_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_VS_OBJS) $(LIBS)

t/time-test: $(T_TT_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(T_TT_OBJS) $(LIBS)

ifdef CONFIG_HAVE_CUNIT
unittests/unittest: $(UT_OBJS) $(UT_TARGET_OBJS)
	$(QUIET_LINK)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(UT_OBJS) $(UT_TARGET_OBJS) -lcunit $(LIBS)
endif

clean: FORCE
	@rm -f .depend $(FIO_OBJS) $(GFIO_OBJS) $(OBJS) $(T_OBJS) $(UT_OBJS) $(PROGS) $(T_PROGS) $(T_TEST_PROGS) core.* core gfio unittests/unittest FIO-VERSION-FILE *.[do] lib/*.d oslib/*.[do] crc/*.d engines/*.[do] profiles/*.[do] t/*.[do] unittests/*.[do] unittests/*/*.[do] config-host.mak config-host.h y.tab.[ch] lex.yy.c exp/*.[do] lexer.h
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
	  git clone https://github.com/hgst/libzbc &&		 	\
	  (cd libzbc &&						 	\
	   ./autogen.sh &&					 	\
	   ./configure --prefix=/usr &&				 	\
	   make -j &&						 	\
	   sudo make install)						\
	fi &&					 			\
	sudo t/zbd/run-tests-against-regular-nullb &&		 	\
	if [ -e /sys/module/null_blk/parameters/zoned ]; then		\
		sudo t/zbd/run-tests-against-zoned-nullb;	 	\
	fi

install: $(PROGS) $(SCRIPTS) tools/plot/fio2gnuplot.1 FORCE
	$(INSTALL) -m 755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/fio.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/fio_generate_plots.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/plot/fio2gnuplot.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 $(SRCDIR)/tools/hist/fiologparser_hist.py.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 755 -d $(DESTDIR)$(sharedir)
	$(INSTALL) -m 644 $(SRCDIR)/tools/plot/*gpm $(DESTDIR)$(sharedir)/

.PHONY: test fulltest
