#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h> // for fabs, sqrt
#include "face_api.h"
#include "csv_reader.h"

// Path relative to execution directory (project root)
#define DB_PATH "../feature_extraction/face_vectors.csv"
#define NUM_AUTOMATED_TESTS 100

// Helper function to calculate plaintext cosine similarity
float plaintext_cosine_similarity(const float* vec1, const float* vec2) {
    float dot_product = 0.0f;
    float norm_sq1 = 0.0f;
    float norm_sq2 = 0.0f;

    for (int i = 0; i < FACE_VECTOR_DIM; i++) {
        dot_product += vec1[i] * vec2[i];
        norm_sq1 += vec1[i] * vec1[i];
        norm_sq2 += vec2[i] * vec2[i];
    }

    return dot_product / (sqrtf(norm_sq1) * sqrtf(norm_sq2));
}

void test_pair(const char* label, const float* reference_template, const float* probe_template) {
    printf("\n=== Testing %s ===\n", label);
    
    // 1. Setup Environment
    HSS_CRS crs;
    face_auth_setup(&crs);
    
    // --- Phase 1: Enrollment ---
    Auth_Cref c_ref;
    Auth_Witness witness;
    face_auth_enroll(&crs, reference_template, &c_ref, &witness);
    printf("[Enrollment] User registered. Server stores C_ref. User keeps Witness.\n");
    
    // --- Phase 2: Authentication ---
    
    // Step 1: Challenge (Server)
    Auth_Cprb c_prb;
    Auth_ServerVerifyState verify_state;
    face_auth_challenge(&crs, probe_template, &c_ref, &c_prb, &verify_state);
    printf("[Challenge] Server captured live probe, generated C_prb, sent to User.\n");
    
    // Step 2: Response (User)
    Auth_Response response;
    face_auth_respond(&crs, &c_prb, &witness, &response);
    printf("[Response]  User answered challenge using local Witness.\n");
    
    // Step 3: Verify (Server)
    int match = face_auth_verify(&response, &verify_state);
    
    // Output Verdict
    if (match) {
        printf("Verdict: MATCH (Access Granted)\n");
    } else {
        printf("Verdict: NO MATCH (Access Denied)\n");
    }
}

void run_comprehensive_security_tests(const FaceRecord* db, int db_count, 
                                      const FaceRecord* target_registered, 
                                      const FaceRecord* target_live) {
    printf("\n=======================================================\n");
    printf("=== COMPREHENSIVE AUTOMATED SECURITY EVALUATION =====\n");
    printf("=======================================================\n");

    HSS_CRS crs;
    face_auth_setup(&crs);

    // Setup Target (Enrollment)
    Auth_Cref target_cref;
    Auth_Witness target_witness; 
    face_auth_enroll(&crs, target_registered->vector, &target_cref, &target_witness);

    // Setup a stolen witness (from a different theoretical session of the target)
    Auth_Cref dummy_cref;
    Auth_Witness stolen_witness;
    face_auth_enroll(&crs, target_live->vector, &dummy_cref, &stolen_witness);

    int imposter_success = 0;
    int stolen_state_success = 0;
    int target_state_success = 0;
    int combined_success = 0;

    printf("Running attacks using %d random imposter faces from DB...\n", NUM_AUTOMATED_TESTS);

    for (int i = 0; i < NUM_AUTOMATED_TESTS; i++) {
        // Pick random imposter
        int idx = rand() % db_count;
        const FaceRecord* imposter = &db[idx];
        if (strcmp(imposter->identity, target_registered->identity) == 0) {
            i--; continue; // Skip if it's the target person
        }

        // --- Attack 1: Pure Imposter (Wrong face, correct witness for that wrong face) ---
        Auth_Cref adv_cref;
        Auth_Witness adv_witness;
        face_auth_enroll(&crs, imposter->vector, &adv_cref, &adv_witness);

        Auth_Cprb challenge1;
        Auth_ServerVerifyState verify1;
        face_auth_challenge(&crs, imposter->vector, &target_cref, &challenge1, &verify1);

        Auth_Response resp1;
        face_auth_respond(&crs, &challenge1, &adv_witness, &resp1);
        if (face_auth_verify(&resp1, &verify1)) imposter_success++;

        // --- Attack 2: Stolen State (Wrong face, stolen target witness) ---
        Auth_Cprb challenge2;
        Auth_ServerVerifyState verify2;
        face_auth_challenge(&crs, imposter->vector, &target_cref, &challenge2, &verify2);

        Auth_Response resp2;
        face_auth_respond(&crs, &challenge2, &stolen_witness, &resp2);
        if (face_auth_verify(&resp2, &verify2)) stolen_state_success++;


        // --- Attack 3: Combined (Wrong face, random forged witness) ---
        Auth_Cprb challenge3;
        Auth_ServerVerifyState verify3;
        face_auth_challenge(&crs, imposter->vector, &target_cref, &challenge3, &verify3);

        Auth_Witness random_witness;
        for(int j=0; j<sizeof(HSS_StateB); j++) ((uint8_t*)&random_witness)[j] = rand() % 256;
        
        Auth_Response resp3;
        face_auth_respond(&crs, &challenge3, &random_witness, &resp3);
        if (face_auth_verify(&resp3, &verify3)) combined_success++;

        // --- Attack 4: Target State Attack (Wrong face, legitimate target witness) ---
        // This simulates someone having the exact perfect hardware token of the target 
        // but trying to authenticate with a different face.
        Auth_Cprb challenge4;
        Auth_ServerVerifyState verify4;
        face_auth_challenge(&crs, imposter->vector, &target_cref, &challenge4, &verify4);

        Auth_Response resp4;
        face_auth_respond(&crs, &challenge4, &target_witness, &resp4);
        int encrypted_match = face_auth_verify(&resp4, &verify4);
        if (encrypted_match) {
            target_state_success++;
            
            // --- SIDE-BY-SIDE VERIFICATION ---
            float pt_sim = plaintext_cosine_similarity(target_registered->vector, imposter->vector);
            printf("\n[DEBUG] Attack 4 False Accept Triggered!\n");
            printf("        Imposter: %s\n", imposter->filename);
            printf("        Encrypted HSS Verdict: MATCH\n");
            printf("        Plaintext Similarity : %.4f (Threshold: %.2f)\n", pt_sim, (float)FACE_TAU_NUM / FACE_TAU_DEN);
            if (pt_sim >= ((float)FACE_TAU_NUM / FACE_TAU_DEN)) {
                printf("        -> CONCLUSION: This is a Biometric FAR (False Accept), NOT a cryptographic failure.\n");
            } else {
                printf("        -> CONCLUSION: DANGER! Cryptographic logic mismatch!\n");
            }
        }
    }

    printf("\n--- Results for %d Random Imposter Faces ---\n", NUM_AUTOMATED_TESTS);
    printf("1. Pure Imposter Attacks Successful: %d / %d\n", imposter_success, NUM_AUTOMATED_TESTS);
    printf("2. Stolen State Attacks Successful : %d / %d\n", stolen_state_success, NUM_AUTOMATED_TESTS);
    printf("3. Combined Attacks Successful     : %d / %d\n", combined_success, NUM_AUTOMATED_TESTS);
    printf("4. Target State Attacks Successful  : %d / %d\n", target_state_success, NUM_AUTOMATED_TESTS);

    // --- Attack 5: Forged State on Correct Face ---
    printf("\nRunning %d Random Forged State attacks on Correct Live Face...\n", NUM_AUTOMATED_TESTS);
    int forged_success = 0;
    for (int i = 0; i < NUM_AUTOMATED_TESTS; i++) {
        Auth_Cprb challenge5;
        Auth_ServerVerifyState verify5;
        face_auth_challenge(&crs, target_live->vector, &target_cref, &challenge5, &verify5);

        Auth_Witness random_witness;
        for(int j=0; j<sizeof(HSS_StateB); j++) ((uint8_t*)&random_witness)[j] = rand() % 256;
        
        Auth_Response resp5;
        face_auth_respond(&crs, &challenge5, &random_witness, &resp5);
        if (face_auth_verify(&resp5, &verify5)) forged_success++;
    }
    printf("5. Forged State Attacks Successful : %d / %d\n", forged_success, NUM_AUTOMATED_TESTS);
    printf("=======================================================\n");
}

int main() {
    srand(time(NULL));
    printf("Secure Face Authentication Demo (Cosine Similarity Algorithm)\n");
    printf("Phases: 1. Enrollment (User -> Server: C_ref)  2. Auth (Server -> User: Challenge, User -> Server: Response)\n");
    printf("Loading database from %s...\n", DB_PATH);

    // 1. Load DB
    int db_count = 0;
    FaceRecord* db = load_face_db(DB_PATH, &db_count);
    if (!db || db_count == 0) {
        fprintf(stderr, "Error: Failed to load database or database empty.\n");
        return 1;
    }

    // 2. Select Target User (George W Bush)
    const FaceRecord* bush_imgs[2] = {NULL, NULL};
    int bush_found = find_faces_by_identity(db, db_count, "George_W_Bush", bush_imgs, 2);

    if (bush_found < 2) {
        fprintf(stderr, "Error: Could not find enough images for Bush (%d/2).\n", bush_found);
        free(db);
        return 1;
    }

    printf("Target User Selected:\n");
    printf(" - Bush (Registered): %s\n", bush_imgs[0]->filename);
    printf(" - Bush (Live):       %s\n", bush_imgs[1]->filename);

    // 3. Basic Correctness Test (Same Person)
    test_pair("Identity Check: Bush vs Bush (Same Person)", bush_imgs[0]->vector, bush_imgs[1]->vector);

    // 4. Run Automated Comprehensive Security Tests
    // This will test 100 random imposter faces against Bush's enrollment
    run_comprehensive_security_tests(db, db_count, bush_imgs[0], bush_imgs[1]);

    // 5. Cleanup
    free(db);

    return 0;
}
