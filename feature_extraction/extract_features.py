import face_recognition
import os
import csv
import sys

# Configuration
DATASET_DIR = "dataset"
OUTPUT_CSV = "face_vectors.csv"
OUTPUT_HEADER = "face_vectors.h"

def process_images(dataset_path, csv_path, header_path):
    print(f"Starting feature extraction from {dataset_path}...")
    
    vectors = []
    
    # Open CSV for writing
    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["identity", "filename"] + [f"dim_{i}" for i in range(128)])
        
        # Walk through the dataset
        count = 0
        for root, dirs, files in os.walk(dataset_path):
            for file in files:
                if file.lower().endswith(('.png', '.jpg', '.jpeg')):
                    file_path = os.path.join(root, file)
                    identity = os.path.basename(root)
                    
                    try:
                        # Load image
                        image = face_recognition.load_image_file(file_path)
                        
                        # Detect faces and get encodings
                        # We assume one face per image for simplicity in this extraction
                        encodings = face_recognition.face_encodings(image)
                        
                        if len(encodings) > 0:
                            # Take the first face found
                            vec = encodings[0]
                            
                            # Write to CSV
                            row = [identity, file] + list(vec)
                            writer.writerow(row)
                            
                            # Store for C header generation (limit to first few to avoid huge file)
                            if count < 50: 
                                vectors.append((identity, file, vec))
                            
                            count += 1
                            if count % 10 == 0:
                                print(f"Processed {count} images...", end='\r')
                        else:
                            # print(f"No face found in {file}")
                            pass
                            
                    except Exception as e:
                        print(f"Error processing {file}: {e}")

    print(f"\nFinished! Extracted {count} vectors to {csv_path}")
    
    # Generate a C header file with a few samples for easy testing
    with open(header_path, 'w') as hfile:
        hfile.write("#ifndef FACE_VECTORS_H\n#define FACE_VECTORS_H\n\n")
        hfile.write("// Auto-generated face vectors from LFW dataset\n\n")
        
        for idx, (ident, fname, vec) in enumerate(vectors):
            sanitized_ident = ident.replace(" ", "_").replace("-", "_")
            var_name = f"face_{sanitized_ident}_{idx}"
            
            hfile.write(f"// From: {fname}\n")
            hfile.write(f"const float {var_name}[128] = {{\n    ")
            for i, val in enumerate(vec):
                hfile.write(f"{val:.6f}")
                if i < 127:
                    hfile.write(", ")
                    if (i + 1) % 8 == 0:
                        hfile.write("\n    ")
            hfile.write("\n};\n\n")
            
        hfile.write("#endif // FACE_VECTORS_H\n")
    print(f"Generated sample C header at {header_path}")

if __name__ == "__main__":
    if not os.path.exists(DATASET_DIR):
        print(f"Error: Dataset directory '{DATASET_DIR}' not found.")
        sys.exit(1)
        
    process_images(DATASET_DIR, OUTPUT_CSV, OUTPUT_HEADER)
