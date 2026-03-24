CC ?= gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -Wall -O2
CPPFLAGS += -I.

OPENSSL_CFLAGS ?= $(shell $(PKG_CONFIG) --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell $(PKG_CONFIG) --libs openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_CFLAGS) $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lcrypto

ifneq ($(wildcard /usr/local/opt/openssl/include),)
OPENSSL_CFLAGS += -I/usr/local/opt/openssl/include
OPENSSL_LIBS += -L/usr/local/opt/openssl/lib
endif

ifneq ($(wildcard /opt/homebrew/opt/openssl/include),)
OPENSSL_CFLAGS += -I/opt/homebrew/opt/openssl/include
OPENSSL_LIBS += -L/opt/homebrew/opt/openssl/lib
endif
endif

CPPFLAGS += $(OPENSSL_CFLAGS)
LDLIBS += $(OPENSSL_LIBS)

all: hss_nim_test

# --- NIM Core Tests ---
hss_nim_test: hss_core.o hss_test.o
	$(CC) $(CFLAGS) $(CPPFLAGS) -o hss_nim_test hss_core.o hss_test.o $(LDLIBS)

# --- Object Files ---
hss_core.o: hss_core.c hss_core.h hss_config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hss_core.c

hss_test.o: hss_test.c hss_core.h hss_config.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c hss_test.c

clean:
	rm -f *.o hss_nim_test
