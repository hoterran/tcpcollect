CC=gcc -O2
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

libpcap-pfring: dummy
	@cd libpcap-pfring && ./configure && make

libpcap: dummy
	@cd libpcap && ./configure && make

mysqlpcap:LOADLIBES += libpcap/libpcap.a -lpthread
mysqlpcap:CFLAGS += -Ilibpcap -DDEBUG
mysqlpcap: mysqlpcap.c hash.o log.o packet.o protocol.o address.o utils.o adlist.o user.o file_cache.o

#mysqlpcap:LOADLIBES += lib/libpcap.a lib/libpfring.a -lpthread
#mysqlpcap:CFLAGS += -Ilibpcap-pfring
#mysqlpcap: mysqlpcap.c hash.o log.o packet.o protocol.o address.o adlist.o utils.o

clean:
	- rm -f *.o mysqlpcap && cd libpcap && make clean

install:$(TARGET)
	mkdir -p $(BINDIR)
	$(INSTALL) $(TARGET) $(BINDIR)

dummy:



test:user_test
	./user_test

user_test: user.c
	gcc -g -o user_test -D_USER_TEST_ -DDEBUG user.c log.c utils.c adlist.c
