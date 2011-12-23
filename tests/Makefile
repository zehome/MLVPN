CC ?= gcc
CFLAGS += -Wall -ggdb

all: sha1test

sha1test: sha1test.o
	$(CC) $< -o sha1test -lssl

clean:
	rm -rf *.o sha1test
