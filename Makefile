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
ysqlpcap:CFLAGS += -Ilibpcap
mysqlpcap: mysqlpcap.c stats-hash.o log.o process-packet.o mysql-protocol.o local-addresses.o

clean:
	- rm -f *.o mysqlpcap && cd libpcap && make clean

install:$(TARGET)
	mkdir -p $(BINDIR)
	$(INSTALL) $(TARGET) $(BINDIR)

dummy:
