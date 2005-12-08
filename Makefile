CC	= gcc
CFLAGS	= -Wall -O2 -g -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
PROGS	= fio
SCRIPTS = fio_generate_plots

all: depend $(PROGS) $(SCRIPTS)

fio: fio.o fio-io.o fio-ini.o md5.o crc32.o
	$(CC) $(CFLAGS) -o $@ $(filter %.o,$^) -lpthread -laio -lm -lrt

clean:
	-rm -f *.o .depend $(PROGS)

depend:
	@$(CC) -MM $(ALL_CFLAGS) *.c 1> .depend

INSTALL = install
prefix = /usr/local
bindir = $(prefix)/bin

install: $(PROGS) $(SCRIPTS)
	$(INSTALL) -m755 -d $(DESTDIR)$(bindir)
	$(INSTALL) $(PROGS) $(SCRIPTS) $(DESTDIR)$(bindir)

ifneq ($(wildcard .depend),)
include .depend
endif
