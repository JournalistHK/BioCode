#ifndef HSS_CORE_H
#define HSS_CORE_H

#include "hss_config.h"

// ==========================================
// Data Structures (NIM Definition)
// ==========================================

// Common Reference String (crs)
typedef struct {
    uint8_t seed_A[16];
    uint8_t seed_B[16];
} HSS_CRS;

// --- Role A (Alice / Hasher) Structures ---

// Public Encoding A (pe_A) - Previously "Digest d"
// d = A*x + B*u
typedef struct {
    hss_int_t vec_d[HSS_K];
} HSS_PubA;

// Secret State A (st_A)
// Holds the input x and the secret randomness u
typedef struct {
    hss_int_t x[HSS_N]; // Lifted x (in Z_Q)
    hss_int_t u[HSS_T];
} HSS_StateA;

// --- Role B (Bob / Encryptor) Structures ---

// Public Encoding B (pe_B) - Previously "Ciphertext ctx"
// e = A^T*w + chi + Delta*y
// e' = B^T*w + chi
typedef struct {
    hss_int_t vec_e[HSS_N];
    hss_int_t vec_ep[HSS_T];
} HSS_PubB;

// Secret State B (st_B)
// Holds the secret vector w
typedef struct {
    hss_int_t w[HSS_K];
} HSS_StateB;


// ==========================================
// Function Prototypes
// ==========================================

// Setup(1^n, p, q) -> crs
void hss_setup(HSS_CRS *crs);

// --- Role A ---

// Encode_A(crs, x) -> (pe_A, st_A)
// Note: x must be already lifted to Z_Q (centered)
void hss_encode_A(const HSS_CRS *crs, 
                  const hss_int_t *x_lifted, 
                  HSS_PubA *pe_A, 
                  HSS_StateA *st_A);

// Decode_A(crs, pe_B, st_A) -> z_A
hss_int_t hss_decode_A(const HSS_CRS *crs, 
                       const HSS_PubB *pe_B, 
                       const HSS_StateA *st_A);

// --- Role B ---

// Encode_B(crs, y) -> (pe_B, st_B)
// Note: y is in Z_P (standard encoding is fine as it's scaled by Delta)
void hss_encode_B(const HSS_CRS *crs, 
                  const hss_int_t *y_encoded, 
                  HSS_PubB *pe_B, 
                  HSS_StateB *st_B);

// Decode_B(crs, pe_A, st_B) -> z_B
hss_int_t hss_decode_B(const HSS_CRS *crs, 
                       const HSS_PubA *pe_A, 
                       const HSS_StateB *st_B);

// --- Reconstruction ---
// z_A - z_B mod p
hss_int_t hss_reconstruct(hss_int_t z_A, hss_int_t z_B);

#endif
