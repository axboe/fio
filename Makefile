CC	= gcc
DEBUGFLAGS = -D_FORTIFY_SOURCE=2 -DFIO_INC_DEBUG
CPPFLAGS= -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 \
	$(DEBUGFLAGS)
OPTFLAGS= -O2 -fno-omit-frame-pointer -g $(EXTFLAGS)
CFLAGS	= -std=gnu99 -Wwrite-strings -Wall $(OPTFLAGS)
LIBS	= -lm
PROGS	= fio
SCRIPTS = fio_generate_plots
UNAME  := $(shell uname)

SOURCE = gettime.c fio.c ioengines.c init.c stat.c log.c time.c filesetup.c \
		eta.c verify.c memory.c io_u.c parse.c mutex.c options.c \
		rbtree.c smalloc.c filehash.c profile.c debug.c lib/rand.c \
		lib/num2str.c $(wildcard crc/*.c) engines/cpu.c \
		engines/mmap.c engines/sync.c engines/null.c engines/net.c \
		memalign.c

ifeq ($(UNAME), Linux)
  SOURCE += diskutil.c fifo.c blktrace.c helpers.c cgroup.c trim.c \
		engines/libaio.c engines/posixaio.c engines/sg.c \
		engines/splice.c engines/syslet-rw.c engines/guasi.c \
		engines/binject.c profiles/tiobench.c
  LIBS += -lpthread -ldl -lrt -laio
  CFLAGS += -rdynamic
endif
ifeq ($(UNAME), SunOS)
  SOURCE += fifo.c lib/strsep.c helpers.c engines/posixaio.c \
		engines/solarisaio.c
  LIBS	 += -lpthread -ldl -laio -lrt -lnsl -lsocket
  CPPFLAGS += -D__EXTENSIONS__
endif
ifeq ($(UNAME), FreeBSD)
  SOURCE += helpers.c engines/posixaio.c
  LIBS	 += -lpthread -lrt
  CFLAGS += -rdynamic
endif
ifeq ($(UNAME), NetBSD)
  SOURCE += helpers.c engines/posixaio.c
  LIBS	 += -lpthread -lrt
  CFLAGS += -rdynamic
endif
ifeq ($(UNAME), AIX)
  SOURCE += fifo.c helpers.c lib/getopt_long.c engines/posixaio.c
  LIBS	 += -lpthread -ldl -lrt
  CFLAGS += -rdynamic
  CPPFLAGS += -D_LARGE_FILES -D__ppc__
endif
ifeq ($(UNAME), Darwin)
  SOURCE += helpers.c engines/posixaio.c
  LIBS	 += -lpthread -ldl
endif
ifneq (,$(findstring CYGWIN,$(UNAME)))
  SOURCE += engines/windowsaio.c
  LIBS	 += -lpthread -lrt
endif

OBJS = $(SOURCE:.c=.o)

ifneq ($(findstring $(MAKEFLAGS),s),s)
ifndef V
	QUIET_CC	= @echo '   ' CC $@;
	QUIET_DEP	= @echo '   ' DEP $@;
endif
endif

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin
mandir = $(prefix)/man

.c.o:
	$(QUIET_CC)$(CC) -o $@ -c $(CFLAGS) $(CPPFLAGS) $<

fio: $(OBJS)
	$(QUIET_CC)$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

depend:
	$(QUIET_DEP)$(CC) -MM $(CFLAGS) $(CPPFLAGS) $(SOURCE) 1> .depend

$(PROGS): depend

all: depend $(PROGS) $(SCRIPTS)

clean:
	-rm -f .depend $(OBJS) $(PROGS) core.* core

cscope:
	@cscope -b -R

install: $(PROGS) $(SCRIPTS)
	$(INSTALL) -m 755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)
	$(INSTALL) -m 755 -d $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 fio.1 $(DESTDIR)$(mandir)/man1
	$(INSTALL) -m 644 fio_generate_plots.1 $(DESTDIR)$(mandir)/man1

ifneq ($(wildcard .depend),)
include .depend
endif
