CC=gcc
CFLAGS=-g -pedantic -std=gnu17 -Wall -Werror -Wextra -Wno-deprecated-declarations
LDLIBS=-lcrypto

ifeq ($(shell uname),Darwin)
    CFLAGS  += -I/opt/homebrew/opt/openssl@3/include
    LDFLAGS += -L/opt/homebrew/opt/openssl@3/lib
endif

.PHONY: all
all: nyufile

nyufile: nyufile.o

nyufile.o: nyufile.c

.PHONY: clean
clean:
	rm -f *.o nyufile
