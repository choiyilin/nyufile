CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra
LDFLAGS=-lcrypto

ifeq ($(shell uname),Darwin)
    CFLAGS  += -I/opt/homebrew/opt/openssl@3/include
    CFLAGS  += -Wno-deprecated-declarations
    LDFLAGS := -L/opt/homebrew/opt/openssl@3/lib -lcrypto
endif

.PHONY: all clean

all: nyufile

nyufile: nyufile.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

nyufile.o: nyufile.c

clean:
	rm -f *.o nyufile
