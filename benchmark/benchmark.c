#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <math.h> // for fabs, sqrt
#include "face_api.h"
#include "csv_reader.h"

// Path relative to execution directory
#define DB_PATH "../feature_extraction/face_vectors.csv"

// Helper: Get time in microseconds
long long time_in_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000000LL + tv.tv_usec;
}

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

void run_benchmarks(const FaceRecord* ref_record, const FaceRecord* probe_record) {
    printf("\n=======================================================\n");
    printf("=== PERFORMANCE BENCHMARKS ============================\n");
    printf("=======================================================\n");

    int iters_enc = 1000;
    int iters_plain = 1000000;
    
    HSS_CRS crs;
    face_auth_setup(&crs);
    
    Auth_Cref c_ref;
    Auth_Witness witness;
    Auth_Cprb c_prb;
    Auth_ServerVerifyState verify_state;
    Auth_Response response;
    
    long long start, end;
    
    printf("Benchmarking Encrypted Protocol (%d iterations)...\n", iters_enc);
    
    // 1. Benchmark Enrollment
    start = time_in_us();
    for (int i = 0; i < iters_enc; i++) {
        face_auth_enroll(&crs, ref_record->vector, &c_ref, &witness);
    }
    end = time_in_us();
    double time_enroll = (double)(end - start) / iters_enc;
    
    // 2. Benchmark Challenge
    start = time_in_us();
    for (int i = 0; i < iters_enc; i++) {
        face_auth_challenge(&crs, probe_record->vector, &c_ref, &c_prb, &verify_state);
    }
    end = time_in_us();
    double time_challenge = (double)(end - start) / iters_enc;
    
    // 3. Benchmark Respond
    start = time_in_us();
    for (int i = 0; i < iters_enc; i++) {
        face_auth_respond(&crs, &c_prb, &witness, &response);
    }
    end = time_in_us();
    double time_respond = (double)(end - start) / iters_enc;
    
    // 4. Benchmark Verify
    start = time_in_us();
    for (int i = 0; i < iters_enc; i++) {
        face_auth_verify(&response, &verify_state);
    }
    end = time_in_us();
    double time_verify = (double)(end - start) / iters_enc;
    
    printf("Benchmarking Plaintext Baseline (%d iterations)...\n", iters_plain);
    
    // 5. Benchmark Plaintext
    start = time_in_us();
    volatile float pt_sim = 0; // volatile to prevent optimization
    for (int i = 0; i < iters_plain; i++) {
        pt_sim += plaintext_cosine_similarity(ref_record->vector, probe_record->vector);
    }
    end = time_in_us();
    double time_plaintext = (double)(end - start) / iters_plain;
    
    printf("\nAverage Time per Operation:\n");
    printf("-------------------------------------------------------\n");
    printf("[Encrypted] Phase 1: Enrollment      : %8.2f us\n", time_enroll);
    printf("[Encrypted] Phase 2: Challenge       : %8.2f us\n", time_challenge);
    printf("[Encrypted] Phase 2: Response        : %8.2f us\n", time_respond);
    printf("[Encrypted] Phase 2: Verify          : %8.2f us\n", time_verify);
    printf("-------------------------------------------------------\n");
    double total_auth_time = time_challenge + time_respond + time_verify;
    printf("Total Encrypted Auth (Chall+Resp+Ver): %8.2f us (%.2f ms)\n", total_auth_time, total_auth_time / 1000.0);
    printf("-------------------------------------------------------\n");
    printf("[Plaintext] Cosine Similarity        : %8.2f us\n", time_plaintext);
    printf("-------------------------------------------------------\n");
    printf("Efficiency Loss (Enc Auth / Plain)   : %.0f x slower\n", total_auth_time / time_plaintext);
    printf("=======================================================\n");
}

int main() {
    printf("Secure Face Authentication Demo - BENCHMARK TOOL\n");
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

    printf("Using images for benchmark:\n");
    printf(" - Reference: %s\n", bush_imgs[0]->filename);
    printf(" - Probe:     %s\n", bush_imgs[1]->filename);

    // 3. Run Performance Benchmarks
    run_benchmarks(bush_imgs[0], bush_imgs[1]);

    // 4. Cleanup
    free(db);

    return 0;
}
