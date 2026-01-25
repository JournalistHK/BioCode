#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "hss_core.h"

// ==========================================
// NIM Core Unit Test (128-bit Support)
// ==========================================

// Helper to print __int128 in Hex
void print_u128_val(hss_int_t val) {
    uint64_t upper = (uint64_t)(val >> 64);
    uint64_t lower = (uint64_t)val;
    if (upper > 0) {
        printf("0x%" PRIx64 "%016" PRIx64, upper, lower);
    } else {
        printf("0x%" PRIx64, lower);
    }
}

// Print vector of hss_int_t (128-bit)
void print_vec_u128(const char* label, const hss_int_t* v, int len) {
    printf("%s: [", label);
    for(int i=0; i< (len > 5 ? 5 : len); i++) {
        print_u128_val(v[i]);
        printf(", ");
    }
    printf("...]\n");
}

// Print vector of int32_t
void print_vec_signed(const char* label, const int32_t* v, int len) {
    printf("%s: [", label);
    for(int i=0; i< (len > 5 ? 5 : len); i++) {
        printf("%d, ", v[i]);
    }
    printf("...]\n");
}

// Print single __int128 labeled
void print_label_u128(const char* label, hss_int_t val) {
    printf("%s: ", label);
    print_u128_val(val);
    printf("\n");
}

hss_int_t to_mod_p(int64_t val) {
    if (val < 0) {
        hss_int_t abs_val = (hss_int_t)(-val);
        hss_int_t rem = abs_val % HSS_P;
        if (rem == 0) return 0;
        return HSS_P - rem;
    }
    return (hss_int_t)val % HSS_P;
}

hss_int_t to_mod_q_centered(int64_t val) {
    if (val < 0) {
        return HSS_Q - (hss_int_t)(-val);
    }
    return (hss_int_t)val;
}

int64_t from_mod_p(hss_int_t val) {
    hss_int_t p_half = HSS_P / 2;
    if (val > p_half) {
        hss_int_t diff = HSS_P - val;
        // Check if diff fits in int64
        if (diff > 9223372036854775807ULL) { 
            // Should not happen for valid inner products within range
            return -1; 
        }
        return -(int64_t)diff;
    }
    return (int64_t)val;
}

void run_verbose_nim_test() {
    printf("\n--- Starting Verbose NIM Test ---\n");
    
    HSS_CRS crs;
    hss_setup(&crs);
    printf("[Setup] CRS generated (Seeds for A and B).\n");

    // Inputs
    int32_t x_real[HSS_N];
    int32_t y_real[HSS_N];
    hss_int_t x_lifted_q[HSS_N]; 
    hss_int_t y_encoded_p[HSS_N]; 
    int64_t true_inner_product = 0;

    printf("[Input Generation]\n");
    printf("  Generating inputs in range [-65536, 65536] to simulate real quantized vectors.\n");
    
    for(int i=0; i<HSS_N; i++) {
        int32_t val_x = (rand() % 131073) - 65536; 
        int32_t val_y = (rand() % 131073) - 65536;
        
        x_real[i] = val_x;
        y_real[i] = val_y;
        
        true_inner_product += ((int64_t)x_real[i] * y_real[i]);
        
        x_lifted_q[i] = to_mod_q_centered(x_real[i]);
        y_encoded_p[i] = to_mod_p(y_real[i]);
    }
    
    print_vec_signed("  x (int32)", x_real, HSS_N);
    print_vec_u128  ("  x (Z_Q)  ", x_lifted_q, HSS_N);
    print_vec_signed("  y (int32)", y_real, HSS_N);
    print_vec_u128  ("  y (Z_P)  ", y_encoded_p, HSS_N);

    printf("  Expected Inner Product: %lld\n", (long long)true_inner_product);

    // Hasher (Alice)
    HSS_PubA pe_A;
    HSS_StateA st_A;
    hss_encode_A(&crs, x_lifted_q, &pe_A, &st_A);
    
    printf("\n[Alice Step 1] Encoded x -> Digest d\n");
    print_vec_u128("  Digest d (Z_Q)", pe_A.vec_d, HSS_K);
    
    // Encryptor (Bob)
    HSS_PubB pe_B;
    HSS_StateB st_B;
    hss_encode_B(&crs, y_encoded_p, &pe_B, &st_B);
    
    printf("\n[Bob Step 1] Encoded y -> Ciphertext (e, e')\n");
    print_vec_u128("  Ctx e  (Z_Q)", pe_B.vec_e, HSS_N);
    print_vec_u128("  Ctx e' (Z_Q)", pe_B.vec_ep, HSS_T);
    
    // Cross Decode
    printf("\n[Cross Decode]\n");
    
    hss_int_t z_A = hss_decode_A(&crs, &pe_B, &st_A);
    print_label_u128("  Alice decodes Bob's Ctx -> Share z_A", z_A);
    
    hss_int_t z_B = hss_decode_B(&crs, &pe_A, &st_B);
    print_label_u128("  Bob decodes Alice's Dgst -> Share z_B", z_B);
    
    // Reconstruct
    printf("\n[Result]\n");
    
    hss_int_t result_mod_p = hss_reconstruct(z_A, z_B);
    int64_t result_recovered = from_mod_p(result_mod_p);

    print_label_u128("  z_A - z_B (mod P)", result_mod_p);
    printf("  Recovered Signed:  %lld\n", (long long)result_recovered);
    printf("  True Value:        %lld\n", (long long)true_inner_product);
    
    if (result_recovered == true_inner_product) {
        printf("  STATUS: SUCCESS\n");
    } else {
        printf("  STATUS: FAILURE (Mismatch)\n");
    }
}

int main() {
    srand(time(NULL));
    printf("=== NIM Core Unit Test (Verbose) ===\n");
    // Hardcode display as config is complex type now
    printf("Config: N=%d, K=%d, P=2^%d, Q=2^%d\n", HSS_N, HSS_K, HSS_LOG2_P, HSS_LOG2_Q);
    
    run_verbose_nim_test();

    return 0;
}
