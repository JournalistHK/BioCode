CC=cc

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
	# Mac OS X detection
	ifneq ($(wildcard /opt/homebrew/opt/openssl),)
		OPENSSL_DIR=/opt/homebrew/opt/openssl
	else
		OPENSSL_DIR=/usr/local/opt/openssl
	endif
else
	# Linux default
	OPENSSL_DIR=/usr
endif

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -std=gnu11 -Wall -Wextra -I$(OPENSSL_INCLUDE_DIR) #-DDEBUG_LOGS
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl -lm

all:
	$(CC) $(CFLAGS) -o generate_a generate_a.c $(LDFLAGS) 
	$(CC) $(CFLAGS) -c lwekex.c
	$(CC) $(CFLAGS) -o test test.c lwekex.o $(LDFLAGS) 

test: all
	./test

clean:
	rm -f *.o
	rm -f generate_a
	rm -f test

prettyprint:
	astyle --style=java --indent=tab --pad-header --pad-oper --align-pointer=name --align-reference=name --suffix=none *.c *.h
