#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "../hss_core/hss_core.h"

// Helper: Get time in microseconds
long long time_in_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

void run_nim_benchmarks() {
    printf("\n=======================================================\n");
    printf("=== NIM / HSS CORE BENCHMARKS =========================\n");
    printf("=======================================================\n");

    int iters = 5000;
    
    HSS_CRS crs;
    hss_setup(&crs);

    // Dummy data
    hss_int_t x[HSS_N];
    hss_int_t y[HSS_N];
    for (int i = 0; i < HSS_N; i++) {
        x[i] = rand() % HSS_P;
        y[i] = rand() % HSS_Q; 
    }

    HSS_PubB pub_B;
    HSS_StateB state_B;
    HSS_PubA pub_A;
    HSS_StateA state_A;
    hss_int_t z_A, z_B;

    long long start, end;
    double time_enc_A, time_enc_B, time_dec_A, time_dec_B, time_recon;

    printf("Benchmarking primitive functions (%d iterations)...\n", iters);

    // 1. hss_encode_A (Server)
    start = time_in_us();
    for (int i = 0; i < iters; i++) {
        hss_encode_A(&crs, y, &pub_A, &state_A);
    }
    end = time_in_us();
    time_enc_A = (double)(end - start) / iters;

    // 2. hss_encode_B (Client)
    start = time_in_us();
    for (int i = 0; i < iters; i++) {
        hss_encode_B(&crs, x, &pub_B, &state_B);
    }
    end = time_in_us();
    time_enc_B = (double)(end - start) / iters;

    // 3. hss_decode_A (Server evaluation)
    start = time_in_us();
    for (int i = 0; i < iters; i++) {
        z_A = hss_decode_A(&crs, &pub_B, &state_A);
    }
    end = time_in_us();
    time_dec_A = (double)(end - start) / iters;

    // 4. hss_decode_B (Client evaluation)
    start = time_in_us();
    for (int i = 0; i < iters; i++) {
        z_B = hss_decode_B(&crs, &pub_A, &state_B);
    }
    end = time_in_us();
    time_dec_B = (double)(end - start) / iters;

    // 5. hss_reconstruct
    start = time_in_us();
    for (int i = 0; i < iters; i++) {
        volatile hss_int_t res = hss_reconstruct(z_A, z_B);
        (void)res;
    }
    end = time_in_us();
    time_recon = (double)(end - start) / iters;

    printf("\nAverage Time per Primitive:\n");
    printf("-------------------------------------------------------\n");
    printf("hss_encode_A (Server setup)    : %8.2f us\n", time_enc_A);
    printf("hss_encode_B (Client setup)    : %8.2f us\n", time_enc_B);
    printf("hss_decode_A (Server eval)     : %8.2f us\n", time_dec_A);
    printf("hss_decode_B (Client eval)     : %8.2f us\n", time_dec_B);
    printf("hss_reconstruct                : %8.2f us\n", time_recon);
    printf("=======================================================\n");
}

int main() {
    srand(time(NULL));
    run_nim_benchmarks();
    return 0;
}
