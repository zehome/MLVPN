CC ?= gcc
CFLAGS += -Wall -ggdb -Wno-format-zero-length

OBJS = configlib.o tool.o debug.o mlvpn.o buffer.o privsep_fdpass.o privsep.o \
       ps_status.o wrr.o

all: mlvpn

mlvpn: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o mlvpn

adduser:
	adduser --system --home /var/spool/mlvpn --shell /bin/false --disabled-password --disabled-login mlvpn

test: testconfiglib.o configlib.o debug.o tool.o
	$(CC) $(CFLAGS) $? -o testconfiglib

man:
	$(MAKE) -C man

install:
	echo "Todo!"

dist:
	git archive --format tar.gz --prefix "mlvpn-1.0/" --output "../mlvpn_1.0.orig.tar.gz" master

clean:
	rm -rf *.o mlvpn
	$(MAKE) -C man clean
