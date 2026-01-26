# Face Feature Extraction

This directory contains tools to extract 128-dimensional face feature vectors from the LFW dataset.

## Setup

1.  Ensure you have Python 3 installed.
2.  Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```
    *Note: `face_recognition` requires `dlib`, which may require CMake installed on your system.*

## Usage

1.  The LFW dataset should be extracted into the `dataset/` subdirectory (this should have been done automatically).
2.  Run the extraction script:
    ```bash
    python3 extract_features.py
    ```

## Output

*   `face_vectors.csv`: A CSV file containing the identity, filename, and the 128 float values for each detected face.
*   `face_vectors.h`: A C header file containing the first 50 vectors formatted as C arrays, ready to be copy-pasted into your C projects (like `hss_real_face_test.c`).
