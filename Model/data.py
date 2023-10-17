import os
import joblib
import pandas as pd
import hashlib
from datetime import datetime

# Specify the path to your trained Logistic Regression model (.pkl file)
model_file_path = r'C:\Users\student\Documents\Model\final.pkl'

# Specify the path to the file you want to analyze
file_to_analyze =  r'C:\Users\student\Documents\Model\j.txt.txt'  # Update with the file path

# Load the trained model
if os.path.exists(model_file_path):
    loaded_model = joblib.load(model_file_path)
    print("Model loaded successfully.")
else:
    print("Model file does not exist at:", model_file_path)
    exit()  # Exit if the model file is not found

# Calculate MD5 and SHA256 checksums of the file
def calculate_checksums(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as file:
        while chunk := file.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

md5_checksum, sha256_checksum = calculate_checksums(file_to_analyze)
print(f"MD5 Checksum: {md5_checksum}")
print(f"SHA256 Checksum: {sha256_checksum}")

# Add date and time to the timestamp
timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
print(f"Date and Time: {timestamp}")

# Replace this part with code to extract feature values from the file
# Extract the actual feature values from the file
# Example: Read bytes from the file and convert them to a numerical feature
# You need to adapt this part to your specific file format and data
with open(file_to_analyze, "rb") as file:
    data = file.read()
    # Extract feature values from 'data' variable
    # Example: Extract a 4-byte integer from a specific offset in the file
    feature_value = int.from_bytes(data[0:4], byteorder='little')  # Example feature extraction

# Prepare the data for prediction
file_data = {
    'Magic': [0.1],  # Replace with the actual value for 'Magic'
    'Subsystem': [0.2],  # Replace with the actual value for 'Subsystem'
    'DllCharacteristics': [0.3],  # Replace with the actual value for 'DllCharacteristics'
    'e_maxalloc': [0.4],
    'e_crlc': [0.5],
    'e_cparhdr': [0.6],
    'e_minalloc': [0.7],
    'e_magic': [0.1],  # Replace with the actual value for 'e_magic'
    'e_cblp': [0.2],  # Replace with the actual value for 'e_cblp'
    'e_cp': [0.3],     # Replace with the actual value for 'e_cp'
    'e_maxalloc': [0.4],
    'e_crlc': [0.5],
    'e_cparhdr': [0.6],
    'e_minalloc': [0.7],
}

# Create a DataFrame with the expected column names
X_new = pd.DataFrame(file_data)

# Make predictions
prediction = loaded_model.predict(X_new)

# Define a maliciousness score (you can adjust this scoring logic)
maliciousness_score = (sum(prediction) / len(prediction)) * 100

# Display the prediction result (malicious or not) along with MD5, SHA256, date and time, and maliciousness score
print(f"Maliciousness Score: {maliciousness_score:.2f}%")
if maliciousness_score > 50:  # You can adjust this threshold
    print("Prediction: The file is classified as Malware.")
else:
    print("Prediction: The file is classified as Not Malware.")
