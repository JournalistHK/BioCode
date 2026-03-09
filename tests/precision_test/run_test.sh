#!/bin/bash
# run_test.sh
cd "$(dirname "$0")"

echo "Running precision tests..."
for scale in 65536 32768 16384 8192 4096 2048 1024 512 256 128; do
    echo "========================================="
    echo "Testing SCALE: $scale"
    gcc -Wall -O2 -I../../face_recognition -I../../hss_core -DHSS_SCALE=$scale.0 \
        -I/usr/local/opt/openssl/include \
        -I/opt/homebrew/opt/openssl/include \
        -o test_precision test_precision.c ../../face_recognition/face_api.c ../../face_recognition/csv_reader.c ../../hss_core/hss_core.c \
        -L/usr/local/opt/openssl/lib \
        -L/opt/homebrew/opt/openssl/lib -lcrypto
    
    ./test_precision
    if [ $? -ne 0 ]; then
        echo "FAILED at scale $scale"
    else
        echo "PASSED at scale $scale"
    fi
done
