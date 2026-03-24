CC ?= gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -Wall -O2
CPPFLAGS += -I. -I../hss_core

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
LDLIBS += $(OPENSSL_LIBS) -lm

# We depend on the object file from the sibling directory
CORE_OBJ = ../hss_core/hss_core.o

all: face_auth_demo

face_auth_demo: face_api.o main.o csv_reader.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o face_auth_demo face_api.o main.o csv_reader.o $(CORE_OBJ) $(LDLIBS)

face_api.o: face_api.c face_api.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c face_api.c

main.o: main.c face_api.h csv_reader.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c main.c

csv_reader.o: csv_reader.c csv_reader.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c csv_reader.c

# Ensure core object is built
$(CORE_OBJ):
	$(MAKE) -C ../hss_core hss_core.o

clean:
	rm -f *.o face_auth_demo
