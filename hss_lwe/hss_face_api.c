#include "hss_face_api.h"
#include <math.h>
#include <stdlib.h> // for NULL if needed

// Helper: Quantize Float -> Modular Integer (Z_Q or Z_P)
static int64_t quantize(float val) {
    return (int64_t)round(val * HSS_SCALE);
}

// Helper: Modulo Wrappers (Copied from local utils or exposed if refactored)
// For now, we inline simple logic or redeclare helpers to keep it self-contained
static hss_int_t to_mod_p(int64_t val) {
    int64_t m = val % (int64_t)HSS_P;
    if (m < 0) m += HSS_P;
    return (hss_int_t)m;
}

static hss_int_t to_mod_q_centered(int64_t val) {
    return (hss_int_t)(val & HSS_Q_MASK);
}

static int64_t from_mod_p(hss_int_t val) {
    if (val >= (HSS_P / 2)) {
        return (int64_t)val - (int64_t)HSS_P;
    }
    return (int64_t)val;
}

// --- Implementation ---

void face_auth_setup(HSS_CRS *crs) {
    hss_setup(crs);
}

void face_client_prepare_query(const HSS_CRS *crs, const float *face_vec, EncryptedFaceQuery *query) {
    hss_int_t x_lifted[HSS_N];
    
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(face_vec[i]);
        x_lifted[i] = to_mod_q_centered(val_q);
    }
    
    hss_encode_A(crs, x_lifted, &query->pub, &query->state);
}

void face_server_prepare_db(const HSS_CRS *crs, const float *face_vec, EncryptedFaceDB *db_entry) {
    hss_int_t y_encoded[HSS_N];
    
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(face_vec[i]);
        y_encoded[i] = to_mod_p(val_q);
    }
    
    hss_encode_B(crs, y_encoded, &db_entry->pub, &db_entry->state);
}

float face_secure_compare(const HSS_CRS *crs, const EncryptedFaceQuery *query, const EncryptedFaceDB *db_entry) {
    // 1. Cross Decode (NIM Computation)
    // Client computes z_A using Server's public data
    hss_int_t z_A = hss_decode_A(crs, &db_entry->pub, &query->state);
    
    // Server computes z_B using Client's public data
    hss_int_t z_B = hss_decode_B(crs, &query->pub, &db_entry->state);
    
    // 2. Reconstruction (Combine Shares)
    // In a real protocol, one party would send their share to the other.
    hss_int_t result_mod_p = hss_reconstruct(z_A, z_B);
    
    // 3. Dequantization
    int64_t result_int = from_mod_p(result_mod_p);
    float score = (float)result_int / (HSS_SCALE * HSS_SCALE);
    
    return score;
}

int face_is_match(float similarity_score) {
    return similarity_score > FACE_SIMILARITY_THRESHOLD;
}
