#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csv_reader.h"

// Increased buffer for larger N (e.g., 512, 1024)
#define MAX_LINE_LEN (HSS_N * 48 + 512)

FaceRecord* load_face_db(const char* csv_path, int *count) {
    FILE* file = fopen(csv_path, "r");
    if (!file) {
        perror("Failed to open CSV file");
        return NULL;
    }

    // 1. Count lines to allocate memory (first pass)
    int line_count = 0;
    char *buffer = malloc(MAX_LINE_LEN);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    while (fgets(buffer, MAX_LINE_LEN, file)) {
        line_count++;
    }
    
    // Check if empty or just header
    if (line_count <= 1) {
        free(buffer);
        fclose(file);
        *count = 0;
        return NULL;
    }

    int data_count = line_count - 1; // Exclude header
    FaceRecord* db = (FaceRecord*)malloc(sizeof(FaceRecord) * data_count);
    if (!db) {
        perror("Failed to allocate memory for DB");
        free(buffer);
        fclose(file);
        return NULL;
    }

    // 2. Read data (second pass)
    rewind(file);
    
    // Skip header
    if (!fgets(buffer, MAX_LINE_LEN, file)) {
        free(db);
        free(buffer);
        fclose(file);
        return NULL;
    }

    int idx = 0;
    while (fgets(buffer, MAX_LINE_LEN, file) && idx < data_count) {
        // Clear vector first for zero-padding
        memset(db[idx].vector, 0, sizeof(float) * FACE_VECTOR_DIM);

        // Parse Identity
        char* token = strtok(buffer, ",");
        if (!token) continue;
        strncpy(db[idx].identity, token, MAX_IDENTITY_LEN - 1);
        db[idx].identity[MAX_IDENTITY_LEN - 1] = '\0';

        // Parse Filename
        token = strtok(NULL, ",");
        if (!token) continue;
        strncpy(db[idx].filename, token, MAX_FILENAME_LEN - 1);
        db[idx].filename[MAX_FILENAME_LEN - 1] = '\0';

        // Parse Vectors (up to FACE_VECTOR_DIM)
        int dim = 0;
        while (dim < FACE_VECTOR_DIM) {
            token = strtok(NULL, ",");
            if (!token) break;
            db[idx].vector[dim] = strtof(token, NULL);
            dim++;
        }

        // We accept records even if they have fewer dimensions (zero-padded above)
        if (dim > 0) {
            idx++;
        }
    }

    free(buffer);
    fclose(file);
    *count = idx;
    printf("Successfully loaded %d face records from %s (Dim: %d, Ring Degree: %d)\n", idx, csv_path, idx > 0 ? (int)FACE_VECTOR_DIM : 0, HSS_N);
    return db;
}

int find_faces_by_identity(const FaceRecord* db, int db_count, 
                           const char* target_identity, 
                           const FaceRecord** results, int max_results) 
{
    int found = 0;
    for (int i = 0; i < db_count && found < max_results; i++) {
        if (strcmp(db[i].identity, target_identity) == 0) {
            results[found++] = &db[i];
        }
    }
    return found;
}
