#CC	= /opt/intel/cce/9.1.045/bin/icc
CC	= gcc -W
DEBUGFLAGS = -D_FORTIFY_SOURCE=2
OPTFLAGS= -O2 -g $(EXTFLAGS)
CFLAGS	= -Wwrite-strings -Wall -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 $(OPTFLAGS) $(DEBUGFLAGS) -rdynamic
PROGS	= fio
SCRIPTS = fio_generate_plots
OBJS = gettime.o fio.o ioengines.o init.o stat.o log.o time.o md5.o crc32.o \
	filesetup.o eta.o verify.o memory.o io_u.o parse.o mutex.o options.o \
	rbtree.o diskutil.o fifo.o blktrace.o

OBJS += engines/cpu.o
OBJS += engines/libaio.o
OBJS += engines/mmap.o
OBJS += engines/posixaio.o
OBJS += engines/sg.o
OBJS += engines/splice.o
OBJS += engines/sync.o
OBJS += engines/null.o
OBJS += engines/net.o
OBJS += engines/syslet-rw.o
OBJS += engines/guasi.o

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin

all: $(PROGS) $(SCRIPTS)

fio: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) $(EXTLIBS) -lpthread -lm -ldl -laio -lrt

clean:
	-rm -f *.o .depend cscope.out $(PROGS) engines/*.o core.* core

depend:
	@$(CC) -MM $(ALL_CFLAGS) *.c engines/*.c 1> .depend

cscope:
	@cscope -b

$(PROGS): | depend

install: $(PROGS) $(SCRIPTS)
	$(INSTALL) -m755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)

ifneq ($(wildcard .depend),)
include .depend
endif
