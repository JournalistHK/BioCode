#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <math.h> // for fabs
#include "face_api.h"
#include "csv_reader.h"

// Path relative to execution directory (project root)
#define DB_PATH "../feature_extraction/face_vectors.csv"

void test_pair(const char* label, const float* face_x, const float* face_y) {
    printf("\n=== Testing %s ===\n", label);
    
    // 1. Setup Environment
    HSS_CRS crs;
    face_auth_setup(&crs);
    
    // 2. Client (Bob) Step 1: Prepare Query x
    FaceQueryPacket1 client_packet1;
    ClientState client_state;
    face_client_step1_prepare(&crs, face_x, &client_packet1, &client_state);
    printf("[Client/Bob] Step 1: Query x prepared and encrypted.\n");
    
    // 3. Server (Alice) Step 1: Process Query x with y
    FaceServerPacket1 server_packet;
    ServerState server_state;
    face_server_step1_process(&crs, face_y, &client_packet1, &server_packet, &server_state);
    printf("[Server/Alice] Step 1: Query processed against y. Shares prepared.\n");
    
    // 4. Client (Bob) Step 2: Finalize Share z_B
    FaceQueryPacket2 client_packet2;
    face_client_step2_compute(&crs, &server_packet, &client_state, &client_packet2);
    printf("[Client/Bob] Step 2: Response share z_B computed.\n");
    
    // 5. Server (Alice) Step 2: Decide
    int match = face_server_step2_decide(&client_packet2, &server_state);
    
    // 6. Output Verdict
    if (match) {
        printf("Verdict: MATCH (Access Granted)\n");
    } else {
        printf("Verdict: NO MATCH (Access Denied)\n");
    }
}

int main() {
    printf("Secure Face Authentication Demo (Cosine Similarity Algorithm)\n");
    printf("Roles: Bob (Client) has x, Alice (Server) has y\n");
    printf("Loading database from %s...\n", DB_PATH);

    // 1. Load DB
    int db_count = 0;
    FaceRecord* db = load_face_db(DB_PATH, &db_count);
    if (!db || db_count == 0) {
        fprintf(stderr, "Error: Failed to load database or database empty.\n");
        return 1;
    }

    // 2. Select Test Candidates
    const FaceRecord* bush_imgs[2] = {NULL, NULL};
    const FaceRecord* powell_imgs[1] = {NULL};

    int bush_found = find_faces_by_identity(db, db_count, "George_W_Bush", bush_imgs, 2);
    int powell_found = find_faces_by_identity(db, db_count, "Colin_Powell", powell_imgs, 1);

    if (bush_found < 2 || powell_found < 1) {
        fprintf(stderr, "Error: Could not find enough images for Bush (%d/2) or Powell (%d/1).\n", bush_found, powell_found);
        free(db);
        return 1;
    }

    printf("Selected:\n");
    printf(" - Bush 1: %s\n", bush_imgs[0]->filename);
    printf(" - Bush 2: %s\n", bush_imgs[1]->filename);
    printf(" - Powell: %s\n", powell_imgs[0]->filename);

    // 3. Run Tests
    // Test 1: Same Person (Bush 1 vs Bush 2)
    test_pair("Identity Check: Bush vs Bush (Same Person)", bush_imgs[0]->vector, bush_imgs[1]->vector);

    // Test 2: Imposter (Powell vs Bush 1)
    test_pair("Identity Check: Powell vs Bush (Imposter)", powell_imgs[0]->vector, bush_imgs[0]->vector);

    // 4. Cleanup
    free(db);
    
    return 0;
}