CC=gcc
CFLAGS= -g -Wall 
INSTALL=/usr/bin/install
INSTALLDIR=/usr/local
BINDIR=$(INSTALLDIR)/bin

COMPILE.c = $(CC) $(CFLAGS) $(INCLUDE) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(CC) $(INCLUDE) $(LDFLAGS) $(TARGET_ARCH)
LINK.c = $(CC) $(CFLAGS) $(INCLUDE) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)
VPATH=./

TARGET=libpcap mysqlpcap 

all:$(TARGET) 

libpcap:dummy
	@cd libpcap && ./configure && make

mysqlpcap:LOADLIBES += libpcap/libpcap.a
mysqlpcap:CFLAGS += -Ilibpcap
mysqlpcap: mysqlpcap.c hash.o log.o packet.o protocol.o address.o

clean:
	- rm -f *.o mysqlpcap && cd libpcap && make clean

install:$(TARGET)
	mkdir -p $(BINDIR)
	$(INSTALL) $(TARGET) $(BINDIR)

dummy:
