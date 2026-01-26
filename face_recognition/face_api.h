#ifndef FACE_API_H
#define FACE_API_H

#include "../hss_core/hss_core.h"

// ==========================================
// Face Recognition Configuration
// ==========================================
#define FACE_SIMILARITY_THRESHOLD 0.6f

// ==========================================
// Data Structures
// ==========================================

// Encrypted/Encoded Face Template
// This is what you would store in a database.
typedef struct {
    HSS_PubB pub;
    HSS_StateB state;
} EncryptedFaceDB; // For Server/Bob side

// Query Template
// This is what the user sends to authenticate.
typedef struct {
    HSS_PubA pub;
    HSS_StateA state;
} EncryptedFaceQuery; // For Client/Alice side

// ==========================================
// API Functions
// ==========================================

// 1. Setup Environment (Generate CRS)
void face_auth_setup(HSS_CRS *crs);

// 2. Client: Prepare Query Vector (Float -> Encrypted Query)
void face_client_prepare_query(const HSS_CRS *crs, 
                               const float *face_vec, 
                               EncryptedFaceQuery *query);

// 3. Server: Prepare Database Vector (Float -> Encrypted DB Entry)
void face_server_prepare_db(const HSS_CRS *crs, 
                            const float *face_vec, 
                            EncryptedFaceDB *db_entry);

// 4. Secure Comparison Protocol
// Returns the similarity score (float) derived from secure computation
// Note: In a real MPC, Alice and Bob would compute partial shares z_A, z_B locally.
// Here we simulate the exchange and reconstruction.
float face_secure_compare(const HSS_CRS *crs, 
                          const EncryptedFaceQuery *query, 
                          const EncryptedFaceDB *db_entry);

// 5. Decision Helper
int face_is_match(float similarity_score);

#endif
