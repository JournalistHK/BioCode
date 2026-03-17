#include "face_api.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Helper: Quantize Float -> Modular Integer (Z_Q or Z_P)
static int64_t quantize(float val) {
    return (int64_t)round(val * HSS_SCALE);
}

// Helper: Modulo Wrappers
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

// Phase 1: Enrollment
// User computes Cref (to send to Server) and Witness (to keep local)
void face_auth_enroll(const HSS_CRS *crs, 
                      const float *reference_template, 
                      Auth_Cref *c_ref_out,
                      Auth_Witness *witness_out) 
{
    hss_int_t x_encoded[HSS_N];
    
    uint64_t sum_sq = 0;
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(reference_template[i]);
        x_encoded[i] = to_mod_p(val_q); 
        sum_sq += (uint64_t)(val_q * val_q); 
    }
    
    // Encode Vector
    hss_encode_B(crs, x_encoded, &c_ref_out->pub_vec, &witness_out->state_vec);
    
    // Encode Truncated Norm
    // Pad norm to 128 dimensions (only first element matters, rest are 0)
    hss_int_t norm_encoded[HSS_N] = {0};
    uint64_t trunc_norm = sum_sq >> NORM_TRUNC_BITS;
    norm_encoded[0] = to_mod_p(trunc_norm);
    hss_encode_B(crs, norm_encoded, &c_ref_out->pub_norm, &witness_out->state_norm);
}

// Phase 2 - Step 1: Challenge (Server-side)
// Server uses live probe template and stored Cref to generate a Challenge (Cprb)
void face_auth_challenge(const HSS_CRS *crs, 
                         const float *probe_template,
                         const Auth_Cref *c_ref,
                         Auth_Cprb *c_prb_out,
                         Auth_ServerVerifyState *verify_state_out)
{
    hss_int_t y_lifted[HSS_N];
    
    uint64_t sum_sq = 0;
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(probe_template[i]);
        y_lifted[i] = to_mod_q_centered(val_q); 
        sum_sq += (uint64_t)(val_q * val_q);
    }
    
    // Encode Vector (Generate PubA)
    hss_encode_A(crs, y_lifted, &c_prb_out->pub_vec, &verify_state_out->state_vec);
    
    // Compute Server's Partial Share (z_A)
    verify_state_out->z_S_vec = hss_decode_A(crs, &c_ref->pub_vec, &verify_state_out->state_vec);
    
    // Encode Truncated Norm (Generate PubA for norm)
    hss_int_t norm_lifted[HSS_N] = {0};
    uint64_t trunc_norm = sum_sq >> NORM_TRUNC_BITS;
    norm_lifted[0] = to_mod_q_centered(trunc_norm);
    hss_encode_A(crs, norm_lifted, &c_prb_out->pub_norm, &verify_state_out->state_norm);
    
    // Compute Server's Partial Share for Norm
    verify_state_out->z_S_norm = hss_decode_A(crs, &c_ref->pub_norm, &verify_state_out->state_norm);
}

// Phase 2 - Step 2: Response (User-side)
// User uses their secret Witness to answer the Server's Challenge
void face_auth_respond(const HSS_CRS *crs,
                       const Auth_Cprb *c_prb,
                       const Auth_Witness *witness,
                       Auth_Response *response_out)
{
    response_out->z_U_vec = hss_decode_B(crs, &c_prb->pub_vec, &witness->state_vec);
    response_out->z_U_norm = hss_decode_B(crs, &c_prb->pub_norm, &witness->state_norm);
}

// Phase 2 - Step 3: Verify (Server-side)
// Server reconstructs the similarity score and makes the final decision
int face_auth_verify(const Auth_Response *response,
                     const Auth_ServerVerifyState *verify_state)
{
    // 1. Reconstruct Inner Product (in Z_P)
    hss_int_t res_dot_mod = hss_reconstruct(verify_state->z_S_vec, response->z_U_vec);
    int64_t val_dot = from_mod_p(res_dot_mod);
    
    // 2. Reconstruct Norm Product
    hss_int_t res_norm_mod = hss_reconstruct(verify_state->z_S_norm, response->z_U_norm);
    int64_t val_norm_prod = from_mod_p(res_norm_mod);
    
    // ==========================================
    // SECURITY PATCH: Bound/Range Checking
    // ==========================================
    if (val_dot > MAX_EXPECTED_IP || val_dot < -MAX_EXPECTED_IP) {
        // Silently fail to avoid flooding logs during bulk security tests
        // printf("[SECURITY ALERT] Reconstructed Inner Product exceeds mathematical bounds! (Value: %lld)\n", (long long)val_dot);
        // printf("[SECURITY ALERT] Likely a forged state or incorrect credential.\n");
        return 0; // Fail immediately
    }
    
    if (val_norm_prod <= 0) {
        // Unlikely to happen for real norms unless forgery is involved,
        // or extreme negative noise, but norm prod should be highly positive.
        return 0;
    }
    
    // 3. Check Sign Condition (c1): IP(x, y) > 0
    if (val_dot <= 0) {
        return 0; // Fail
    }
    
    // 4. Check Scaled Cosine Condition (c2)
    unsigned __int128 ip_sq = (unsigned __int128)val_dot * (unsigned __int128)val_dot;
    
    // Shift the norm_prod back up by 2*NORM_TRUNC_BITS to get the original scale.
    unsigned __int128 norm_prod = (unsigned __int128)val_norm_prod << (2 * NORM_TRUNC_BITS);
    
    unsigned __int128 lhs = (unsigned __int128)(FACE_TAU_DEN * FACE_TAU_DEN) * ip_sq;
    unsigned __int128 rhs = (unsigned __int128)(FACE_TAU_NUM * FACE_TAU_NUM) * norm_prod;
    
    return (lhs >= rhs);
}
