CC ?= gcc
CFLAGS += -Wall -ggdb

OBJS = configlib.o tool.o debug.o mlvpn.o buffer.o privsep_fdpass.o privsep.o \
       ps_status.o chap.o wrr.o

all: mlvpn

mlvpn: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o mlvpn -lssl

adduser:
	adduser --system --home /var/spool/mlvpn --shell /bin/false --disabled-password --disabled-login mlvpn

test: testconfiglib.o configlib.o debug.o tool.o
	$(CC) $(CFLAGS) $? -o testconfiglib

clean:
	rm -rf *.o mlvpn
