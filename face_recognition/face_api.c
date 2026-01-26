#include "face_api.h"
#include <math.h>
#include <string.h>
#include <stdlib.h>

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

// 2. Client (Bob) Step 1: Prepare Query (x -> PubB)
void face_client_step1_prepare(const HSS_CRS *crs, 
                               const float *face_x, 
                               FaceQueryPacket1 *packet_out,
                               ClientState *state_out) 
{
    hss_int_t x_encoded[HSS_N];
    hss_int_t x_sq_encoded[HSS_N]; // Scalar packed into vector
    
    // 1. Quantize Vector x and Compute Norm Squared (Scalar)
    int64_t sum_sq = 0;
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(face_x[i]);
        x_encoded[i] = to_mod_p(val_q); // Bob uses Z_P for input y in Encode_B
        
        // Sum of squares in integer domain
        // Warning: Watch for overflow if HSS_SCALE is too large
        // With HSS_SCALE=65536, val_q ~ 10^4. val_q^2 ~ 10^8. Sum(128) ~ 10^10.
        // int64_t is sufficient (up to 9*10^18).
        sum_sq += (val_q * val_q); 
    }
    
    // 2. Pack Norm Squared into a vector (First element, rest 0)
    memset(x_sq_encoded, 0, sizeof(hss_int_t) * HSS_N);
    x_sq_encoded[0] = to_mod_p(sum_sq);
    
    // 3. Encode Both
    hss_encode_B(crs, x_encoded, &packet_out->pub_vec, &state_out->state_vec);
    hss_encode_B(crs, x_sq_encoded, &packet_out->pub_norm, &state_out->state_norm);
}

// 3. Server (Alice) Step 1: Process Query & Prepare Response (y + PubB -> PubA + ShareA)
void face_server_step1_process(const HSS_CRS *crs, 
                               const float *face_y,
                               const FaceQueryPacket1 *client_packet,
                               FaceServerPacket1 *server_packet_out,
                               ServerState *state_out)
{
    hss_int_t y_lifted[HSS_N];
    hss_int_t y_sq_lifted[HSS_N];
    
    // 1. Quantize Vector y and Compute Norm Squared
    int64_t sum_sq = 0;
    for(int i=0; i<HSS_N; i++) {
        int64_t val_q = quantize(face_y[i]);
        y_lifted[i] = to_mod_q_centered(val_q); // Alice uses Z_Q (Lifted)
        
        sum_sq += (val_q * val_q);
    }
    
    // 2. Pack Norm Squared
    memset(y_sq_lifted, 0, sizeof(hss_int_t) * HSS_N);
    y_sq_lifted[0] = to_mod_q_centered(sum_sq);
    
    // 3. Encode Both (Generate PubA)
    hss_encode_A(crs, y_lifted, &server_packet_out->pub_vec, &state_out->state_vec);
    hss_encode_A(crs, y_sq_lifted, &server_packet_out->pub_norm, &state_out->state_norm);
    
    // 4. Compute Server's Partial Shares (z_A)
    // z_A = Decode_A(Client_PubB, Server_StateA)
    state_out->share_A_vec = hss_decode_A(crs, &client_packet->pub_vec, &state_out->state_vec);
    state_out->share_A_norm = hss_decode_A(crs, &client_packet->pub_norm, &state_out->state_norm);
}

// 4. Client (Bob) Step 2: Compute Shares (PubA -> ShareB)
void face_client_step2_compute(const HSS_CRS *crs,
                               const FaceServerPacket1 *server_packet,
                               const ClientState *client_state,
                               FaceQueryPacket2 *packet_out)
{
    // z_B = Decode_B(Server_PubA, Client_StateB)
    packet_out->share_B_vec = hss_decode_B(crs, &server_packet->pub_vec, &client_state->state_vec);
    packet_out->share_B_norm = hss_decode_B(crs, &server_packet->pub_norm, &client_state->state_norm);
}

// 5. Server (Alice) Step 2: Finalize & Decide (ShareA + ShareB -> Decision)
int face_server_step2_decide(const FaceQueryPacket2 *client_shares,
                             const ServerState *server_state)
{
    // 1. Reconstruct Values (in Z_P)
    hss_int_t res_dot_mod = hss_reconstruct(server_state->share_A_vec, client_shares->share_B_vec);
    hss_int_t res_norm_mod = hss_reconstruct(server_state->share_A_norm, client_shares->share_B_norm);
    
    // 2. Convert to Signed Integers
    int64_t val_dot = from_mod_p(res_dot_mod);
    int64_t val_norm = from_mod_p(res_norm_mod);
    
    // 3. Check Sign Condition (c1): IP(x, y) > 0
    // If dot product is negative, angle is > 90 deg, definitely not a match (assuming Tau > 0)
    if (val_dot <= 0) {
        return 0; // Fail
    }
    
    // 4. Check Scaled Cosine Condition (c2)
    // Formula: (1/Tau^2) * IP^2 >= NormProd
    // Integer Version: Den^2 * IP^2 >= Num^2 * NormProd
    
    // Use __int128 to prevent overflow during square/mult
    // IP ~ 10^10, IP^2 ~ 10^20 (exceeds int64)
    unsigned __int128 ip_sq = (unsigned __int128)val_dot * (unsigned __int128)val_dot;
    unsigned __int128 norm_prod = (unsigned __int128)val_norm; // val_norm is already X^2 * Y^2 scaled
    
    unsigned __int128 lhs = (unsigned __int128)(FACE_TAU_DEN * FACE_TAU_DEN) * ip_sq;
    unsigned __int128 rhs = (unsigned __int128)(FACE_TAU_NUM * FACE_TAU_NUM) * norm_prod;
    
    return (lhs >= rhs);
}
