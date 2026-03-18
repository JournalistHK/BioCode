#ifndef CSV_READER_H
#define CSV_READER_H

#include "../hss_core/hss_config.h"

#define FACE_VECTOR_DIM HSS_N
#define MAX_IDENTITY_LEN 64
#define MAX_FILENAME_LEN 64

typedef struct {
    char identity[MAX_IDENTITY_LEN];
    char filename[MAX_FILENAME_LEN];
    float vector[FACE_VECTOR_DIM];
} FaceRecord;

// Loads face records from a CSV file.
// Returns a pointer to an array of FaceRecords allocated on the heap.
// The caller is responsible for freeing the memory (free(records)).
// The 'count' parameter is an output parameter that will hold the number of records loaded.
// Returns NULL on error.
FaceRecord* load_face_db(const char* csv_path, int *count);

// Helper to find specific records by identity name.
// Populates pointers up to max_results. Returns number found.
int find_faces_by_identity(const FaceRecord* db, int db_count, 
                           const char* target_identity, 
                           const FaceRecord** results, int max_results);

#endif
