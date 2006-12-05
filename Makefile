#CC	= /opt/intel/cce/9.1.045/bin/icc
CC	= gcc -W
CFLAGS	= -Wwrite-strings -Wall -O2 -g -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= fio
SCRIPTS = fio_generate_plots
OBJS = gettime.o fio.o ioengines.o init.o stat.o log.o time.o md5.o crc32.o \
	filesetup.o eta.o verify.o memory.o io_u.o parse.o

OBJS += engines/fio-engine-cpu.o
OBJS += engines/fio-engine-libaio.o
OBJS += engines/fio-engine-mmap.o
OBJS += engines/fio-engine-posixaio.o
OBJS += engines/fio-engine-sg.o
OBJS += engines/fio-engine-splice.o
OBJS += engines/fio-engine-sync.o
OBJS += engines/fio-engine-null.o

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib/fio

all: depend $(PROGS) $(SCRIPTS)

fio: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) -lpthread -lm -ldl -laio -lrt

clean:
	-rm -f *.o .depend cscope.out $(PROGS) engines/*.o

depend:
	@$(CC) -MM $(ALL_CFLAGS) *.c 1> .depend

cscope:
	@cscope -b

install: $(PROGS) $(SCRIPTS)
	$(INSTALL) -m755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)
	$(INSTALL) -m755 -d $(DESTDIR) $(libdir)

ifneq ($(wildcard .depend),)
include .depend
endif
