CC	= gcc
CFLAGS	= -W -Wall -O2 -g -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= fio
SCRIPTS = fio_generate_plots
OBJS = fio.o ioengines.o init.o stat.o log.o time.o md5.o crc32.o \
	filesetup.o eta.o verify.o memory.o io_u.o

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin
libdir = $(prefix)/lib/fio

FIO_INST_DIR = $(subst ','\'',$(prefix))

CFLAGS += '-D_INST_PREFIX="$(FIO_INST_DIR)"'

all: depend $(PROGS) $(SCRIPTS)
	$(MAKE) -C engines

fio: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) -lpthread -lm -ldl

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
	$(INSTALL) engines/*.o $(libdir)

ifneq ($(wildcard .depend),)
include .depend
endif
