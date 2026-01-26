#include "hss_core.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

void handleErrors(void) {
    abort();
}

// ==========================================
// Internal Helpers
// ==========================================

static hss_int_t sample_noise() {
    uint8_t bytes[4]; 
    RAND_bytes(bytes, 4);
    int16_t a = 0, b = 0;
    for(int i=0; i<HSS_NOISE_ETA; i++) {
        a += (bytes[0] >> i) & 1;
        b += (bytes[1] >> i) & 1;
    }
    int16_t val = a - b;
    if (val < 0) return HSS_Q + val;
    return (hss_int_t)val;
}

static hss_int_t sample_uniform_q() {
    uint8_t bytes[16]; // 128 bits
    RAND_bytes(bytes, 16);
    hss_int_t val = 0;
    memcpy(&val, bytes, 16);
    return val & HSS_Q_MASK;
}

// Generates Matrix (Rows x Cols) and computes Mat * Vec
static void gen_matrix_mul(hss_int_t *out_result, const hss_int_t *in_vec, int rows, int cols, const uint8_t *seed, int transpose) {
    EVP_CIPHER_CTX *ctx;
    int len;
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, seed, NULL)) handleErrors();
    EVP_CIPHER_CTX_set_padding(ctx, 0);

    memset(out_result, 0, (transpose ? cols : rows) * sizeof(hss_int_t));
    uint8_t aes_in[16];
    uint8_t aes_out[16];

    // We generate one 128-bit element per AES block for simplicity with __int128
    // This is slower than packing, but ensures we fill the large type.
    
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < cols; j++) {
            // Encode i, j into AES input block
            memset(aes_in, 0, 16);
            aes_in[0] = i & 0xFF; aes_in[1] = (i>>8) & 0xFF; aes_in[2] = (i>>16) & 0xFF;
            aes_in[4] = j & 0xFF; aes_in[5] = (j>>8) & 0xFF; aes_in[6] = (j>>16) & 0xFF;
            
            if(1 != EVP_EncryptUpdate(ctx, aes_out, &len, aes_in, 16)) handleErrors();
            
            hss_int_t a_ij;
            memcpy(&a_ij, aes_out, 16);
            a_ij &= HSS_Q_MASK;
            
            if (!transpose) {
                // out[i] += A[i,j] * in[j]
                hss_int_t prod = (a_ij * in_vec[j]) & HSS_Q_MASK;
                out_result[i] = (out_result[i] + prod) & HSS_Q_MASK;
            } else {
                // out[j] += A[i,j] * in[i]
                hss_int_t prod = (a_ij * in_vec[i]) & HSS_Q_MASK;
                out_result[j] = (out_result[j] + prod) & HSS_Q_MASK;
            }
        }
    }
    EVP_CIPHER_CTX_free(ctx);
}

// ==========================================
// Public API Implementation
// ==========================================

void hss_setup(HSS_CRS *crs) {
    if(!RAND_bytes(crs->seed_A, 16)) handleErrors();
    if(!RAND_bytes(crs->seed_B, 16)) handleErrors();
}

// --- Role A (Alice) ---

void hss_encode_A(const HSS_CRS *crs, const hss_int_t *x_lifted, HSS_PubA *pe_A, HSS_StateA *st_A) {
    // 1. Store State (x)
    memcpy(st_A->x, x_lifted, HSS_N * sizeof(hss_int_t));

    // 2. Generate Random u and Store in State
    for(int i=0; i<HSS_T; i++) {
        st_A->u[i] = sample_noise();
    }

    // 3. Compute pe_A (digest d) = A*x + B*u
    hss_int_t Ax[HSS_K];
    hss_int_t Bu[HSS_K];
    
    gen_matrix_mul(Ax, st_A->x, HSS_K, HSS_N, crs->seed_A, 0);
    gen_matrix_mul(Bu, st_A->u, HSS_K, HSS_T, crs->seed_B, 0);
    
    for(int i=0; i<HSS_K; i++) {
        pe_A->vec_d[i] = (Ax[i] + Bu[i]) & HSS_Q_MASK;
    }
}

hss_int_t hss_decode_A(const HSS_CRS *crs, const HSS_PubB *pe_B, const HSS_StateA *st_A) {
    hss_int_t sum = 0;
    
    // e^T * x
    for(int i=0; i<HSS_N; i++) {
        hss_int_t prod = (pe_B->vec_e[i] * st_A->x[i]) & HSS_Q_MASK;
        sum = (sum + prod) & HSS_Q_MASK;
    }
    
    // e'^T * u
    for(int i=0; i<HSS_T; i++) {
        hss_int_t prod = (pe_B->vec_ep[i] * st_A->u[i]) & HSS_Q_MASK;
        sum = (sum + prod) & HSS_Q_MASK;
    }
    
    // Rounding
    return (sum + (HSS_DELTA / 2)) / HSS_DELTA;
}

// --- Role B (Bob) ---

void hss_encode_B(const HSS_CRS *crs, const hss_int_t *y_encoded, HSS_PubB *pe_B, HSS_StateB *st_B) {
    // 1. Generate Secret w
    for(int i=0; i<HSS_K; i++) {
        st_B->w[i] = sample_uniform_q();
    }
    
    // 2. Compute e = A^T * w + chi + Delta * y
    hss_int_t ATw[HSS_N];
    gen_matrix_mul(ATw, st_B->w, HSS_K, HSS_N, crs->seed_A, 1); // Transpose
    
    for(int i=0; i<HSS_N; i++) {
        hss_int_t noise = sample_noise();
        hss_int_t msg_scaled = (y_encoded[i] * HSS_DELTA) & HSS_Q_MASK;
        pe_B->vec_e[i] = (ATw[i] + noise + msg_scaled) & HSS_Q_MASK;
    }
    
    // 3. Compute e' = B^T * w + chi
    hss_int_t BTw[HSS_T];
    gen_matrix_mul(BTw, st_B->w, HSS_K, HSS_T, crs->seed_B, 1); // Transpose
    
    for(int i=0; i<HSS_T; i++) {
        hss_int_t noise = sample_noise();
        pe_B->vec_ep[i] = (BTw[i] + noise) & HSS_Q_MASK;
    }
}

hss_int_t hss_decode_B(const HSS_CRS *crs, const HSS_PubA *pe_A, const HSS_StateB *st_B) {
    hss_int_t dot_prod = 0;
    for(int i=0; i<HSS_K; i++) {
        hss_int_t prod = (st_B->w[i] * pe_A->vec_d[i]) & HSS_Q_MASK;
        dot_prod = (dot_prod + prod) & HSS_Q_MASK;
    }
    
    // Rounding
    return (dot_prod + (HSS_DELTA / 2)) / HSS_DELTA;
}

// --- Reconstruction ---

hss_int_t hss_reconstruct(hss_int_t z_A, hss_int_t z_B) {
    // We need signed arithmetic here.
    // Since hss_int_t is unsigned 128-bit, and P is 60-bit.
    // If z_A < z_B, the result should wrap modulo P.
    
    if (z_A >= z_B) {
        return (z_A - z_B) % HSS_P;
    } else {
        // z_A < z_B. Result is negative.
        // In mod P: (z_A - z_B) = P - (z_B - z_A)
        hss_int_t diff = z_B - z_A;
        return HSS_P - (diff % HSS_P); // If diff % P == 0, returns P which is 0 mod P.
    }
}