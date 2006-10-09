CC	= gcc
CFLAGS	= -Wall -O2 -W -shared -rdynamic -fPIC
ALL_CFLAGS = $(CFLAGS) -I.. -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64
OBJS	= fio-engine-sync.o fio-engine-splice.o fio-engine-mmap.o fio-engine-libaio.o fio-engine-posixaio.o fio-engine-sg.o fio-engine-cpu.o

all: depend $(OBJS)

depend:
	@$(CC) -MM $(ALL_CFLAGS) *.c 1> .depend

clean:
	-rm -f *.o $(OBJS) .depend

%.o: %.c
	$(CC) $(ALL_CFLAGS) -o $*.o $<

ifneq ($(wildcard .depend),)
include .depend
endif
