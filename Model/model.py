from sklearn.impute import SimpleImputer

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer  # Add this import
from sklearn.metrics import accuracy_score, classification_report
import joblib

# Load your dataset
data = pd.read_csv('dataset_malwares.csv')

# Feature Engineering: Adding a new feature 'SumFeature' as an example
data['SumFeature'] = data['e_cblp'] + data['e_cp'] + data['e_maxalloc']

# Drop rows with missing values (NaN)
data = data.dropna()

# Drop duplicate rows
data = data.drop_duplicates()

# Define your target variable 'Malware' and features
X = data.drop(columns=['Malware'])
y = data['Malware']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

# Define which columns are numeric and categorical based on your DataFrame
numeric_features = [
    'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',
    # Include 'SumFeature' in numeric features
]

categorical_features = [
    'Magic', 'Subsystem', 'DllCharacteristics'
]

# Create transformers for numeric and categorical features
numeric_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='median')),
    ('scaler', StandardScaler())
])

categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

# Combine the transformers using ColumnTransformer
preprocessor = ColumnTransformer(
    transformers=[
        ('num', numeric_transformer, numeric_features),
        ('cat', categorical_transformer, categorical_features)
    ])

# Create the full pipeline with preprocessing and logistic regression
clf = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', LogisticRegression())
])

# Fit the model
clf.fit(X_train, y_train)

# Make predictions
y_pred = clf.predict(X_test)

# Evaluate the model
accuracy = accuracy_score(y_test, y_pred)
report = classification_report(y_test, y_pred)

# Print evaluation metrics
print(f"Accuracy: {accuracy}")
print("Classification Report:")
print(report)

# Save the trained model to a file
model_file_path = 'final.pkl'
joblib.dump(clf, model_file_path)
print(f"Model saved to {model_file_path}")
