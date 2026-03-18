#ifndef HSS_CORE_H
#define HSS_CORE_H

#include "hss_config.h"

// ==========================================
// Data Structures (RLWE NIM Definition)
// ==========================================

// Representation of a polynomial in R_q = Z_q[x] / (x^N + 1)
typedef struct {
    hss_int_t coeffs[HSS_N];
} HSS_Poly;

// Common Reference String (crs)
typedef struct {
    uint8_t seed_A[16];
    uint8_t seed_B[16];
} HSS_CRS;

// --- Role A (Alice / Hasher) Structures ---

// Public Encoding A (pe_A) - Digest d(x)
typedef struct {
    HSS_Poly poly_d;
} HSS_PubA;

// Secret State A (st_A) - Input x and noise u(x)
typedef struct {
    HSS_Poly poly_x; // Lifted x (in Z_Q)
    HSS_Poly poly_u; // Secret noise/mask
} HSS_StateA;

// --- Role B (Bob / Encryptor) Structures ---

// Public Encoding B (pe_B) - Ciphertexts e(x), ep(x)
typedef struct {
    HSS_Poly poly_e;
    HSS_Poly poly_ep;
} HSS_PubB;

// Secret State B (st_B) - Secret key w(x)
typedef struct {
    HSS_Poly poly_w;
} HSS_StateB;


// ==========================================
// RLWE Math Primitives
// ==========================================

// Polynomial multiplication over R_q = Z_q[x] / (x^N + 1)
// Handles the negative-wrap around: x^N = -1 (mod q)
void poly_mul(const HSS_Poly *a, const HSS_Poly *b, HSS_Poly *res);

// Generates a random polynomial from a seed (ExpandA/B)
void poly_expand(HSS_Poly *p, const uint8_t *seed);

// ==========================================
// HSS Protocol API
// ==========================================

// Setup(1^n, p, q) -> crs
void hss_setup(HSS_CRS *crs);

// --- Role A ---
void hss_encode_A(const HSS_CRS *crs, 
                  const hss_int_t *x_raw, 
                  HSS_PubA *pe_A, 
                  HSS_StateA *st_A);

hss_int_t hss_decode_A(const HSS_CRS *crs, 
                       const HSS_PubB *pe_B, 
                       const HSS_StateA *st_A);

// --- Role B ---
void hss_encode_B(const HSS_CRS *crs, 
                  const hss_int_t *y_raw, 
                  HSS_PubB *pe_B, 
                  HSS_StateB *st_B);

hss_int_t hss_decode_B(const HSS_CRS *crs, 
                       const HSS_PubA *pe_A, 
                       const HSS_StateB *st_B);

// --- Reconstruction ---
hss_int_t hss_reconstruct(hss_int_t z_A, hss_int_t z_B);

#endif
