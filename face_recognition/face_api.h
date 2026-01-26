#ifndef FACE_API_H
#define FACE_API_H

#include "../hss_core/hss_core.h"

// ==========================================
// Face Recognition Configuration
// ==========================================
// 阈值 Tau (0.0 - 1.0)
// 我们将其表示为分数 (NUM/DEN) 以进行整数运算
// Tau = 0.6 -> 3/5
#define FACE_TAU_NUM 3
#define FACE_TAU_DEN 5

// ==========================================
// Data Structures
// ==========================================

// Client (Bob) Packet 1: Initial Query
// Sends Public Keys for both Vector and Norm of x
typedef struct {
    HSS_PubB pub_vec;
    HSS_PubB pub_norm;
} FaceQueryPacket1;

// Server (Alice) Packet 1: Server's Public Keys
// Sends Public Keys of y so Client can compute its share
typedef struct {
    HSS_PubA pub_vec;
    HSS_PubA pub_norm;
} FaceServerPacket1;

// Client (Bob) Packet 2: Client's Computed Shares
// Sends partial decryption shares (z_B) to Server
typedef struct {
    hss_int_t share_B_vec;
    hss_int_t share_B_norm;
} FaceQueryPacket2;

// Client State (Kept Local)
// Stores Secret State (w) for x
typedef struct {
    HSS_StateB state_vec;
    HSS_StateB state_norm;
} ClientState;

// Server State (Kept Local)
// Stores Secret State (u) for y and its computed shares (z_A)
typedef struct {
    HSS_StateA state_vec;
    HSS_StateA state_norm;
    
    // Server also stores its own computed shares 
    // waiting for Client's response
    hss_int_t share_A_vec;
    hss_int_t share_A_norm;
} ServerState;

// ==========================================
// API Functions
// ==========================================

// 1. Setup Environment (Generate CRS)
void face_auth_setup(HSS_CRS *crs);

// 2. Client (Bob) Step 1: Prepare Query (x -> PubB)
// Input: Raw Float Vector x
// Output: Packet1 to send, State to keep
void face_client_step1_prepare(const HSS_CRS *crs, 
                               const float *face_x, 
                               FaceQueryPacket1 *packet_out,
                               ClientState *state_out);

// 3. Server (Alice) Step 1: Process Query & Prepare Response (y + PubB -> PubA + ShareA)
// Input: Stored Face Vector y, Client's Packet1
// Output: Packet1 to send back, Server State to keep
void face_server_step1_process(const HSS_CRS *crs, 
                               const float *face_y,
                               const FaceQueryPacket1 *client_packet,
                               FaceServerPacket1 *server_packet_out,
                               ServerState *state_out);

// 4. Client (Bob) Step 2: Compute Shares (PubA -> ShareB)
// Input: Server's Packet1, Client's Local State
// Output: Packet2 (z_B) to send to Server
void face_client_step2_compute(const HSS_CRS *crs,
                               const FaceServerPacket1 *server_packet,
                               const ClientState *client_state,
                               FaceQueryPacket2 *packet_out);

// 5. Server (Alice) Step 2: Finalize & Decide (ShareA + ShareB -> Decision)
// Input: Client's Packet2 (z_B), Server's Local State (z_A)
// Output: 1 (Match) / 0 (No Match)
int face_server_step2_decide(const FaceQueryPacket2 *client_shares,
                             const ServerState *server_state);

#endif
