import numpy as np
import pickle
import hashlib  # Import hashlib for file hashing

# Load your trained classifier from a saved file
with open('model.py', 'rb') as model_file:
    clf = pickle.load(model_file)

def extract_features(file_path):
    # Implement your feature extraction logic here
    # You can use any relevant techniques for analyzing the content of the file

    # For simplicity, let's create a placeholder dictionary with example features
    features = {
        'feature1': 0.75,  # Example feature 1
        'feature2': 128,   # Example feature 2
        # Add more features as needed
    }

    return features

def analyze_file(file_path):
    try:
        # Extract features from the file
        extracted_features = extract_features(file_path)

        if extracted_features is not None:
            # Make a prediction using the trained model
            prediction = clf.predict([list(extracted_features.values())])

            # Display the result
            if prediction == 1:
                print("File is classified as Malware.")
            else:
                print("File is classified as Not Malware.")
        else:
            print("Feature extraction failed. Check your extraction logic.")
    except Exception as e:
        print("An error occurred while analyzing the file:", str(e))

def hash_file(file_path):
    try:
        # Create a hash object
        hasher = hashlib.md5()

        # Open the file and read it in binary mode
        with open(file_path, 'rb') as file:
            # Read the file in chunks to handle large files
            while True:
                chunk = file.read(8192)  # 8KB chunks
                if not chunk:
                    break
                hasher.update(chunk)

        # Get the MD5 hash of the file
        file_hash = hasher.hexdigest()

        return file_hash
    except Exception as e:
        print("An error occurred while hashing the file:", str(e))
        return None

# Specify the path to the file you want to analyze
file_to_analyze = 'C:\\Users\\student\\Documents\\malw\\new.txt'  # Update with the file path

# Analyze the file
analyze_file(file_to_analyze)

# Hash the file to compare with known malware hashes
file_hash = hash_file(file_to_analyze)
if file_hash:
    # Replace with a list of known malware hashes
    known_malware_hashes = ["hash1", "hash2", "hash3"]  # Add known malware hashes
    if file_hash in known_malware_hashes:
        print("File hash matches known malware.")
    else:
        print("File hash does not match known malware.")
