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
// RLWE Math Primitives
// ==========================================

// Polynomial multiplication over R_q = Z_q[x] / (x^N + 1)
// Complexity: O(N^2) - Efficient for N=128, 256
void poly_mul(const HSS_Poly *a, const HSS_Poly *b, HSS_Poly *res) {
    hss_int_t temp[2 * HSS_N] = {0};
    
    // 1. Standard polynomial multiplication (Convolution)
    for (int i = 0; i < HSS_N; i++) {
        for (int j = 0; j < HSS_N; j++) {
            hss_int_t prod = (a->coeffs[i] * b->coeffs[j]) & HSS_Q_MASK;
            temp[i + j] = (temp[i + j] + prod) & HSS_Q_MASK;
        }
    }
    
    // 2. Reduce modulo (x^N + 1)
    // x^N = -1 (mod q), so x^{N+k} = -x^k
    for (int i = 0; i < HSS_N; i++) {
        hss_int_t high = temp[i + HSS_N];
        // res[i] = temp[i] - temp[i+N]
        if (temp[i] >= high) {
            res->coeffs[i] = (temp[i] - high) & HSS_Q_MASK;
        } else {
            res->coeffs[i] = (HSS_Q - (high - temp[i])) & HSS_Q_MASK;
        }
    }
}

// Generates a random polynomial from a seed using AES-CTR as PRNG
void poly_expand(HSS_Poly *p, const uint8_t *seed) {
    EVP_CIPHER_CTX *ctx;
    int len;
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    
    uint8_t iv[16] = {0};
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, seed, iv)) handleErrors();
    
    uint8_t zero_in[16] = {0};
    uint8_t aes_out[16];
    
    for (int i = 0; i < HSS_N; i++) {
        if(1 != EVP_EncryptUpdate(ctx, aes_out, &len, zero_in, 16)) handleErrors();
        memcpy(&p->coeffs[i], aes_out, 16);
        p->coeffs[i] &= HSS_Q_MASK;
    }
    EVP_CIPHER_CTX_free(ctx);
}

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

static void sample_poly_noise(HSS_Poly *p) {
    for(int i=0; i<HSS_N; i++) {
        p->coeffs[i] = sample_noise();
    }
}

static hss_int_t sample_uniform_q() {
    uint8_t bytes[16];
    RAND_bytes(bytes, 16);
    hss_int_t val = 0;
    memcpy(&val, bytes, 16);
    return val & HSS_Q_MASK;
}

static void sample_poly_uniform(HSS_Poly *p) {
    for(int i=0; i<HSS_N; i++) {
        p->coeffs[i] = sample_uniform_q();
    }
}

// ==========================================
// HSS Protocol Implementation
// ==========================================

void hss_setup(HSS_CRS *crs) {
    if(!RAND_bytes(crs->seed_A, 16)) handleErrors();
    if(!RAND_bytes(crs->seed_B, 16)) handleErrors();
}

// --- Role A (Hasher) ---

void hss_encode_A(const HSS_CRS *crs, const hss_int_t *x_raw, HSS_PubA *pe_A, HSS_StateA *st_A) {
    // 1. Prepare poly_x = sum x_i * z^i
    for(int i=0; i<HSS_N; i++) st_A->poly_x.coeffs[i] = x_raw[i];
    
    // 2. Generate secret mask poly_u
    sample_poly_noise(&st_A->poly_u);
    
    // 3. d(x) = A(x)*x(x) + B(x)*u(x)
    HSS_Poly poly_A, poly_B;
    poly_expand(&poly_A, crs->seed_A);
    poly_expand(&poly_B, crs->seed_B);
    
    HSS_Poly Ax, Bu;
    poly_mul(&poly_A, &st_A->poly_x, &Ax);
    poly_mul(&poly_B, &st_A->poly_u, &Bu);
    
    for(int i=0; i<HSS_N; i++) {
        pe_A->poly_d.coeffs[i] = (Ax.coeffs[i] + Bu.coeffs[i]) & HSS_Q_MASK;
    }
}

hss_int_t hss_decode_A(const HSS_CRS *crs, const HSS_PubB *pe_B, const HSS_StateA *st_A) {
    // [[z]]0 = e(x)*x(x) + ep(x)*u(x)
    HSS_Poly ex, epu;
    poly_mul(&pe_B->poly_e, &st_A->poly_x, &ex);
    poly_mul(&pe_B->poly_ep, &st_A->poly_u, &epu);
    
    // Extract inner product from the (N-1)-th coefficient
    // Due to poly_y being reversed, the inner product is at index N-1
    hss_int_t sum = (ex.coeffs[HSS_N-1] + epu.coeffs[HSS_N-1]) & HSS_Q_MASK;
    
    return (sum + (HSS_DELTA / 2)) / HSS_DELTA;
}

// --- Role B (Encryptor) ---

void hss_encode_B(const HSS_CRS *crs, const hss_int_t *y_raw, HSS_PubB *pe_B, HSS_StateB *st_B) {
    // 1. Generate secret w(x)
    sample_poly_uniform(&st_B->poly_w);
    
    // 2. Prepare poly_y = sum y_i * z^{N-1-i} (REVERSED)
    // This trick ensures that poly_x * poly_y has the inner product at index N-1
    HSS_Poly poly_y_scaled = {0};
    for(int i=0; i<HSS_N; i++) {
        poly_y_scaled.coeffs[HSS_N - 1 - i] = (y_raw[i] * HSS_DELTA) & HSS_Q_MASK;
    }
    
    // 3. e(x) = A(x)*w(x) + chi(x) + Delta*y(x)
    HSS_Poly poly_A, poly_B;
    poly_expand(&poly_A, crs->seed_A);
    poly_expand(&poly_B, crs->seed_B);
    
    HSS_Poly Aw, Bw;
    poly_mul(&poly_A, &st_B->poly_w, &Aw);
    poly_mul(&poly_B, &st_B->poly_w, &Bw);
    
    HSS_Poly noise1, noise2;
    sample_poly_noise(&noise1);
    sample_poly_noise(&noise2);
    
    for(int i=0; i<HSS_N; i++) {
        pe_B->poly_e.coeffs[i] = (Aw.coeffs[i] + noise1.coeffs[i] + poly_y_scaled.coeffs[i]) & HSS_Q_MASK;
        pe_B->poly_ep.coeffs[i] = (Bw.coeffs[i] + noise2.coeffs[i]) & HSS_Q_MASK;
    }
}

hss_int_t hss_decode_B(const HSS_CRS *crs, const HSS_PubA *pe_A, const HSS_StateB *st_B) {
    // [[z]]1 = d(x) * w(x)
    HSS_Poly dw;
    poly_mul(&pe_A->poly_d, &st_B->poly_w, &dw);
    
    // Extract from index N-1
    hss_int_t dot_prod = dw.coeffs[HSS_N-1];
    
    return (dot_prod + (HSS_DELTA / 2)) / HSS_DELTA;
}

hss_int_t hss_reconstruct(hss_int_t z_A, hss_int_t z_B) {
    if (z_A >= z_B) {
        return (z_A - z_B) % HSS_P;
    } else {
        hss_int_t diff = z_B - z_A;
        return HSS_P - (diff % HSS_P);
    }
}
