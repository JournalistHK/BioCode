CC ?= gcc
PKG_CONFIG ?= pkg-config

CFLAGS ?= -Wall -O2
CPPFLAGS += -I. -I../hss_core -I../face_recognition

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

# We depend on the object files from the sibling directories
CORE_OBJ = ../hss_core/hss_core.o
FACE_API_OBJ = ../face_recognition/face_api.o
CSV_READER_OBJ = ../face_recognition/csv_reader.o

all: face_benchmark nim_benchmark

face_benchmark: benchmark.o $(FACE_API_OBJ) $(CSV_READER_OBJ) $(CORE_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o face_benchmark benchmark.o $(FACE_API_OBJ) $(CSV_READER_OBJ) $(CORE_OBJ) $(LDLIBS)

nim_benchmark: benchmark_nim.o $(CORE_OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o nim_benchmark benchmark_nim.o $(CORE_OBJ) $(LDLIBS)

benchmark.o: benchmark.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c benchmark.c

benchmark_nim.o: benchmark_nim.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c benchmark_nim.c

# Ensure dependencies are built
$(CORE_OBJ):
	$(MAKE) -C ../hss_core hss_core.o

$(FACE_API_OBJ) $(CSV_READER_OBJ):
	$(MAKE) -C ../face_recognition face_api.o csv_reader.o

clean:
	rm -f *.o face_benchmark nim_benchmark
