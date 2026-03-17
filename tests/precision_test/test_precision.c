#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "face_api.h"
#include "csv_reader.h"

#define DB_PATH "../../feature_extraction/face_vectors.csv"
#define NUM_PAIRS 500000

static int64_t my_from_mod_p(hss_int_t val) {
    if (val >= (HSS_P / 2)) {
        return (int64_t)val - (int64_t)HSS_P;
    }
    return (int64_t)val;
}

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

int main() {
    srand(42); // deterministic seed for comparison
    int db_count = 0;
    FaceRecord* db = load_face_db(DB_PATH, &db_count);
    if (!db || db_count == 0) return 1;

    HSS_CRS crs;
    face_auth_setup(&crs);

    int mismatches = 0;
    int false_rejects = 0;
    int false_accepts = 0;
    
    double total_absolute_error = 0.0;
    double total_relative_error_pct = 0.0;
    int valid_relative_pairs = 0;

    for (int i = 0; i < NUM_PAIRS; i++) {
        int idx1 = rand() % db_count;
        int idx2;
        
        // Force ~10% of pairs to be the SAME person to properly test FRR
        if (rand() % 10 == 0) {
            // Find another image of the same person
            int found_same = 0;
            // Search nearby in the sorted CSV for the same identity
            for (int j = 1; j < 10; j++) {
                if (idx1 + j < db_count && strcmp(db[idx1].identity, db[idx1+j].identity) == 0) {
                    idx2 = idx1 + j;
                    found_same = 1;
                    break;
                }
                if (idx1 - j >= 0 && strcmp(db[idx1].identity, db[idx1-j].identity) == 0) {
                    idx2 = idx1 - j;
                    found_same = 1;
                    break;
                }
            }
            if (!found_same) {
                // Fallback to random if no other image found
                idx2 = rand() % db_count;
            }
        } else {
            // Random different person (usually) to test FAR
            do {
                idx2 = rand() % db_count;
            } while (idx1 == idx2);
        }

        const float* vec1 = db[idx1].vector;
        const float* vec2 = db[idx2].vector;

        float pt_sim = plaintext_cosine_similarity(vec1, vec2);
        int plaintext_match = (pt_sim >= ((float)FACE_TAU_NUM / FACE_TAU_DEN));

        Auth_Cref c_ref;
        Auth_Witness witness;
        face_auth_enroll(&crs, vec1, &c_ref, &witness);

        Auth_Cprb c_prb;
        Auth_ServerVerifyState verify_state;
        face_auth_challenge(&crs, vec2, &c_ref, &c_prb, &verify_state);

        Auth_Response response;
        face_auth_respond(&crs, &c_prb, &witness, &response);
        int encrypted_match = face_auth_verify(&response, &verify_state);
        
        // Reconstruct inner product to compute Cryptographic Cosine Similarity
        hss_int_t res_dot_mod = hss_reconstruct(verify_state.z_S_vec, response.z_U_vec);
        int64_t val_dot = my_from_mod_p(res_dot_mod);
        
        hss_int_t res_norm_mod = hss_reconstruct(verify_state.z_S_norm, response.z_U_norm);
        int64_t val_norm_prod = my_from_mod_p(res_norm_mod);
        
        double crypto_sim = 0.0;
        if (val_norm_prod > 0) {
            crypto_sim = (double)val_dot / sqrt((double)val_norm_prod * pow(2.0, 2.0 * NORM_TRUNC_BITS));
        }
        
        // Compute Error
        double abs_err = fabs(crypto_sim - (double)pt_sim);
        total_absolute_error += abs_err;
        
        if (fabs((double)pt_sim) > 0.001) {
            double rel_err_pct = (abs_err / fabs((double)pt_sim)) * 100.0;
            total_relative_error_pct += rel_err_pct;
            valid_relative_pairs++;
        }

        if (plaintext_match != encrypted_match) {
            mismatches++;
            if (plaintext_match == 1 && encrypted_match == 0) {
                false_rejects++;
            } else if (plaintext_match == 0 && encrypted_match == 1) {
                false_accepts++;
            }
        }
    }

    printf("Total Pairs Tested: %d\n", NUM_PAIRS);
    printf("Mismatches: %d\n", mismatches);
    printf("False Rejects (Crypto FRR): %d\n", false_rejects);
    printf("False Accepts (Crypto FAR): %d\n", false_accepts);
    
    double avg_abs_error = total_absolute_error / NUM_PAIRS;
    double avg_rel_error_pct = (valid_relative_pairs > 0) ? (total_relative_error_pct / valid_relative_pairs) : 0.0;
    
    printf("Mean Absolute Error (Cosine Dist): %.6f\n", avg_abs_error);
    printf("Average Relative Error Percentage: %.4f%%\n", avg_rel_error_pct);

    free(db);
    return mismatches == 0 ? 0 : 1;
}
