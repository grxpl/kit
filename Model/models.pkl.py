import numpy as np
import pickle
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.linear_model import LogisticRegression  # Import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import os
import warnings
warnings.simplefilter('ignore')
import pandas as pd
import lime
import shap
from sklearn.metrics import cross_val_score, r2_score
from sklearn.metrics import mean_absolute_error, mean_squared_error


df = pd.read_csv('dataset_malwares.csv')

# Loading the dataset
data = pd.read_csv('dataset_malwares.csv')  # Replace 'your_dataset.csv' with your dataset file path


# Show what colummns have nullified values
data.isnull().sum()


def explain_model(model, x_train, explainer_type):
    if explainer_type == 'lime':
        explainer = lime.lime_tabular.LimeTabularExplainer(x_train, mode='classification', feature_names=data.drop(['Label'], axis=1).columns)
    elif explainer_type == 'shap':
        explainer = shap.KernelExplainer(model.predict, x_train)
    else:
        raise ValueError("Invalid explainer type. Choose either 'lime' or 'shap'.")
    
    return explainer

df.head(8)

df.info()

dropped_df = df.drop(['Name', 'Machine', 'TimeDateStamp', 'Malware'], axis=1)

import seaborn as sns
import matplotlib.pyplot as plt

# Convert 'Malware' column to categorical data type
df['Malware'] = df['Malware'].astype('category')

# Create a countplot
ax = sns.countplot(data=df, x='Malware')

# Set custom x-axis labels
ax.set_xticklabels(['Not Malware', 'Malware'])

# Set the y-axis label
ax.set_ylabel('Count')

# Show the plot
plt.show()

# Select a subset of features for the pairplot
selected_features = ['MajorSubsystemVersion', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfImage', 'SizeOfHeaders']

# Add 'Malware' to the selected features for comparison
selected_features.append('Malware')

# Create a pairplot
sns.pairplot(df[selected_features], hue='Malware')
plt.show()

features = ['MajorSubsystemVersion', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfImage', 'SizeOfHeaders', 'SizeOfInitializedData', 
            'SizeOfUninitializedData', 'SizeOfStackReserve', 'SizeOfHeapReserve', 'NumberOfSymbols', 'SectionMaxChar']
i=1

for feature in features:
    plt.figure(figsize=(10, 15))
    ax1 = plt.subplot(len(features), 2, i)
    sns.distplot(df[df['Malware']==1][feature], ax=ax1, kde_kws={'bw': 0.1})
    ax1.set_title(f'Malware', fontsize=10)
    ax2 = plt.subplot(len(features), 2, i+1)
    sns.distplot(df[df['Malware']==0][feature], ax=ax2, kde_kws={'bw': 0.1})
    ax2.set_title(f'Not Malware', fontsize=10)

X = dropped_df
y = df['Malware']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

print("Number of used features:", X_train.shape[1])

import pandas as pd
from sklearn.model_selection import train_test_split

# Load your dataset or create it here
# df = ...

# Assuming 'Malware' is your target variable and other columns are your features
X = df.drop(columns=['Malware'])
y = df['Malware']

# Split the data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=0)

from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression

# Specify categorical columns
categorical_cols = ['Name']

# Create transformers
categorical_transformer = Pipeline(steps=[
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

# Create a preprocessor that applies transformers to specified columns
preprocessor = ColumnTransformer(
    transformers=[
        ('cat', categorical_transformer, categorical_cols)
    ])

# Create the pipeline
clf = Pipeline(steps=[
    ('preprocessor', preprocessor),
    ('classifier', LogisticRegression(solver='liblinear'))
])

# Fit the classifier to the training data
clf.fit(X_train, y_train)

# Predict using the trained classifier on the test data
y_pred = clf.predict(X_test)


# Drop rows with missing values (NaN)
data = data.dropna()

# Drop duplicate rows
data = data.drop_duplicates()


def cross_val(x_train, y_train, model):
    accuracies = cross_val_score(estimator = model, X = x_train, y = y_train, cv=5)
    return accuracies.mean()

def fit_and_evaluate(model, x_train , x_test , y_train , y_test):
    model.fit(x_train, y_train)
    
    model_pred = model.predict(x_test)
    model_cross = cross_val(x_train, y_train, model)
    
    return model_cross

def run_experiment(model, x_train , x_test , y_train , y_test):
    model.fit(x_train, y_train)
    y_pred = model.predict(x_test)
    print("R^2 : ", r2_score(y_test, y_pred))
    print("MAE :", mean_absolute_error(y_test,y_pred))
    print("RMSE:",np.sqrt(mean_squared_error(y_test, y_pred)))
    report=classification_report(y_test,y_pred)
    print(report)

# Assuming 'clf' is your Pipeline with Logistic Regression classifier already trained

# Get the names of all steps in the pipeline
step_names = clf.named_steps.keys()

# Print the step names to inspect them
print("Step Names in the Pipeline:", step_names)

# Now, identify the correct step name for Logistic Regression based on the printed names
# Replace 'logisticregression' with the actual name you find in the printed output
logistic_regression_step_name = 'Replace_With_Actual_Name'

if logistic_regression_step_name in step_names:
    logistic_regression = clf.named_steps[logistic_regression_step_name]
    coefficients = logistic_regression.coef_[0]  # Get the coefficients (importance) from the trained Logistic Regression model
    feature_names = dropped_df.columns.values  # Assuming 'dropped_df' is your DataFrame

    # Create a dictionary to store feature names and their corresponding importance values
    importance_dict = dict(zip(feature_names, np.abs(coefficients)))

    # Sort the importance dictionary by absolute values in descending order
    sorted_importance = dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True))

    # Plot the feature importance
    plt.figure(figsize=(10, 20))
    sns.barplot(x=list(sorted_importance.values()), y=list(sorted_importance.keys()), palette='mako')
    plt.xlabel('Importance Value (Absolute)')
    plt.ylabel('Feature Name')
    plt.title('Feature Importance in Logistic Regression Classifier')
    plt.show()

from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.impute import SimpleImputer
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

# Step 4: Data Preprocessing using ColumnTransformer and Pipeline
numeric_features = ['0', '105', '146', '1', '1.1', '1.2', '0.1', '0.2', '255', '254', '1.3', '0.01', '0.3', '0.4', '0.5']  # Numeric feature names from your dataset
categorical_features = ['udp', 'private', 'SF']  # Categorical feature names from your dataset

numeric_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='median')),  # Impute missing values with median
    ('scaler', StandardScaler())  # Standardize numeric features
])

categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),  # Impute missing values with most frequent value
    ('onehot', OneHotEncoder(handle_unknown='ignore'))  # One-hot encode categorical features
])

preprocessor = ColumnTransformer(
    transformers=[
        ('num', numeric_transformer, numeric_features),
        ('cat', categorical_transformer, categorical_features)
    ])

# Now you can use 'preprocessor' as a preprocessing step in your machine learning pipeline.



from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Assuming you have loaded your dataset into X and y
# X should contain both numeric and categorical features

# Define which columns are numeric and categorical based on your DataFrame
numeric_features = [
    'e_magic', 'e_cblp', 'e_cp', 'e_crlc', 'e_cparhdr', 'e_minalloc', 'e_maxalloc',
    'e_ss', 'e_sp', 'e_csum', 'e_ip', 'e_cs', 'e_lfarlc', 'e_ovno', 'e_oemid',
    'e_oeminfo', 'e_lfanew', 'Machine', 'NumberOfSections', 'TimeDateStamp',
    'PointerToSymbolTable', 'NumberOfSymbols', 'SizeOfOptionalHeader', 'Characteristics',
    'MajorLinkerVersion', 'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
    'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'ImageBase',
    'SectionAlignment', 'FileAlignment', 'MajorOperatingSystemVersion',
    'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
    'MajorSubsystemVersion', 'MinorSubsystemVersion', 'SizeOfHeaders', 'CheckSum',
    'SizeOfImage', 'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve',
    'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
    'SuspiciousImportFunctions', 'SectionsLength', 'SectionMinEntropy', 'SectionMaxEntropy',
    'SectionMinRawsize', 'SectionMaxRawsize', 'SectionMinVirtualsize', 'SectionMaxVirtualsize',
    'SectionMaxPhysical', 'SectionMinPhysical', 'SectionMaxVirtual', 'SectionMinVirtual',
    'SectionMaxPointerData', 'SectionMinPointerData', 'SectionMaxChar', 'SectionMainChar',
    'DirectoryEntryImport', 'DirectoryEntryImportSize', 'DirectoryEntryExport',
    'ImageDirectoryEntryExport', 'ImageDirectoryEntryImport', 'ImageDirectoryEntryResource',
    'ImageDirectoryEntryException', 'ImageDirectoryEntrySecurity'
]

categorical_features = [
    'Magic', 'Subsystem', 'DllCharacteristics'
]

# Create preprocessing steps for numeric and categorical features
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

# Split your data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

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

print(X.columns)

import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, classification_report

# Assuming you have already made predictions y_pred and have ground truth y_test

# Create a confusion matrix
conf_matrix = confusion_matrix(y_test, y_pred)

# Create a heatmap
ax = sns.heatmap(conf_matrix, annot=True, fmt="d", cmap=plt.cm.Blues, cbar=False)

# Set labels for x and y axis
ax.set_xlabel('Predicted labels')
ax.set_ylabel('True labels')

# Display the heatmap
plt.show()

# Generate a classification report
report = classification_report(y_test, y_pred)

# Print the classification reportn

print(report)