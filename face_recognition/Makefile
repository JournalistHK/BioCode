CC = gcc

# OpenSSL Paths
CFLAGS = -Wall -O2 -I. -I../hss_core \
         -I/usr/local/opt/openssl/include \
         -I/opt/homebrew/opt/openssl/include

LDFLAGS = -L/usr/local/opt/openssl/lib \
          -L/opt/homebrew/opt/openssl/lib \
          -lcrypto

# We depend on the object file from the sibling directory
CORE_OBJ = ../hss_core/hss_core.o

all: face_auth_demo

face_auth_demo: face_api.o main.o csv_reader.o $(CORE_OBJ)
	$(CC) $(CFLAGS) -o face_auth_demo face_api.o main.o csv_reader.o $(CORE_OBJ) $(LDFLAGS)

face_api.o: face_api.c face_api.h
	$(CC) $(CFLAGS) -c face_api.c

main.o: main.c face_api.h csv_reader.h
	$(CC) $(CFLAGS) -c main.c

csv_reader.o: csv_reader.c csv_reader.h
	$(CC) $(CFLAGS) -c csv_reader.c

# Ensure core object is built
$(CORE_OBJ):
	$(MAKE) -C ../hss_core hss_core.o

clean:
	rm -f *.o face_auth_demo
