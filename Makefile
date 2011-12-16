CC ?= gcc
CFLAGS += -Wall -ggdb

OBJS = configlib.o tool.o debug.o mlvpn.o buffer.o

all: mlvpn

mlvpn: $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o mlvpn

test: testconfiglib.o configlib.o debug.o tool.o
	$(CC) $(CFLAGS) $? -o testconfiglib

clean:
	rm -rf *.o mlvpn
