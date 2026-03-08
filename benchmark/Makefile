CC = gcc

# OpenSSL Paths
CFLAGS = -Wall -O2 -I. -I../hss_core -I../face_recognition \
         -I/usr/local/opt/openssl/include \
         -I/opt/homebrew/opt/openssl/include

LDFLAGS = -L/usr/local/opt/openssl/lib \
          -L/opt/homebrew/opt/openssl/lib \
          -lcrypto

# We depend on the object files from the sibling directories
CORE_OBJ = ../hss_core/hss_core.o
FACE_API_OBJ = ../face_recognition/face_api.o
CSV_READER_OBJ = ../face_recognition/csv_reader.o

all: face_benchmark nim_benchmark

face_benchmark: benchmark.o $(FACE_API_OBJ) $(CSV_READER_OBJ) $(CORE_OBJ)
	$(CC) $(CFLAGS) -o face_benchmark benchmark.o $(FACE_API_OBJ) $(CSV_READER_OBJ) $(CORE_OBJ) $(LDFLAGS)

nim_benchmark: benchmark_nim.o $(CORE_OBJ)
	$(CC) $(CFLAGS) -o nim_benchmark benchmark_nim.o $(CORE_OBJ) $(LDFLAGS)

benchmark.o: benchmark.c
	$(CC) $(CFLAGS) -c benchmark.c

benchmark_nim.o: benchmark_nim.c
	$(CC) $(CFLAGS) -c benchmark_nim.c

# Ensure dependencies are built
$(CORE_OBJ):
	$(MAKE) -C ../hss_core hss_core.o

$(FACE_API_OBJ) $(CSV_READER_OBJ):
	$(MAKE) -C ../face_recognition face_api.o csv_reader.o

clean:
	rm -f *.o face_benchmark nim_benchmark
