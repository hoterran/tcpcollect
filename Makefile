CC=gcc
CFLAGS= -g -Wall 
INSTALL=/usr/bin/install
INSTALLDIR=/usr/local
BINDIR=$(INSTALLDIR)/bin

INCLUDE=-I/usr/local/include/hiredis
COMPILE.c = $(CC) $(CFLAGS) $(INCLUDE) $(CPPFLAGS) $(TARGET_ARCH) -c
LINK.o = $(CC) $(INCLUDE) $(LDFLAGS) $(TARGET_ARCH)
LINK.c = $(CC) $(CFLAGS) $(INCLUDE) $(CPPFLAGS) $(LDFLAGS) $(TARGET_ARCH)
VPATH=./

TARGET=webdump-agent

$(TARGET):$(TARGET).c /usr/local/lib/libhiredis.a /usr/local/lib/libpcap.a

install:$(TARGET)
	mkdir -p $(BINDIR)
	$(INSTALL) $(TARGET) $(BINDIR)

clean:
	- rm -f *.o $(TARGET)

