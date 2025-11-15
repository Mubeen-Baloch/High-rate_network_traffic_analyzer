#!/usr/bin/env python3
"""
SVM Model Training Script for DDoS Detection
Trains SVM model on CIC-DDoS2019 dataset and exports weights for C runtime
"""

import pandas as pd
import numpy as np
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import argparse
import os

def extract_features(df):
    """Extract features from CIC-DDoS2019 dataset"""
    features = []
    
    # Basic flow features
    features.append(df[' Flow Duration'].values)
    features.append(df[' Total Fwd Packets'].values)
    features.append(df[' Total Backward Packets'].values)
    features.append(df['Total Length of Fwd Packets'].values)
    features.append(df[' Total Length of Bwd Packets'].values)
    
    # Rate features
    features.append(df['Flow Bytes/s'].values)
    features.append(df[' Flow Packets/s'].values)
    
    # Packet size features
    features.append(df[' Fwd Packet Length Mean'].values)
    features.append(df[' Fwd Packet Length Std'].values)
    features.append(df[' Bwd Packet Length Mean'].values)
    features.append(df[' Bwd Packet Length Std'].values)
    
    # Inter-arrival time features
    features.append(df[' Flow IAT Mean'].values)
    features.append(df[' Flow IAT Std'].values)
    features.append(df[' Flow IAT Max'].values)
    features.append(df[' Flow IAT Min'].values)
    
    # Protocol and port features
    features.append(df[' Protocol'].values)
    features.append(df[' Source Port'].values)
    features.append(df[' Destination Port'].values)
    
    # Flag features
    features.append(df['Fwd PSH Flags'].values)
    features.append(df[' Bwd PSH Flags'].values)
    features.append(df[' Fwd URG Flags'].values)
    features.append(df[' Bwd URG Flags'].values)
    
    # Window features
    features.append(df['Init_Win_bytes_forward'].values)
    features.append(df[' Init_Win_bytes_backward'].values)
    
    # Convert to numpy array
    X = np.column_stack(features)
    
    # Handle missing values
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    
    return X

def prepare_labels(df):
    """Prepare labels for training"""
    # Map labels: BENIGN = 0, DDoS = 1
    labels = (df[' Label'] != 'BENIGN').astype(int)
    return labels.values

def train_svm_model(X, y, config):
    """Train SVM model with given configuration"""
    print(f"Training SVM with {len(X)} samples and {X.shape[1]} features")
    
    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Normalize features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    # Train SVM
    svm = SVC(
        kernel='rbf',
        gamma=config['gamma'],
        C=config['C'],
        random_state=42,
        probability=True
    )
    
    print("Training SVM model...")
    svm.fit(X_train_scaled, y_train)
    
    # Evaluate model
    y_pred = svm.predict(X_test_scaled)
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Calculate accuracy
    accuracy = svm.score(X_test_scaled, y_test)
    print(f"\nTest Accuracy: {accuracy:.4f}")
    
    return svm, scaler

def export_model_to_c(svm, scaler, output_file):
    """Export trained SVM model to C arrays"""
    print(f"Exporting model to {output_file}")
    
    # Get model parameters
    support_vectors = svm.support_vectors_
    dual_coef = svm.dual_coef_[0]  # Support vector weights
    bias = svm.intercept_[0]
    gamma = svm.gamma
    n_features = support_vectors.shape[1]
    n_support_vectors = support_vectors.shape[0]
    
    # Get normalization parameters
    feature_means = scaler.mean_
    feature_stds = scaler.scale_
    
    with open(output_file, 'w') as f:
        f.write("// Auto-generated SVM model for DDoS detection\n")
        f.write("// Generated from CIC-DDoS2019 dataset\n\n")
        
        f.write("#ifndef SVM_MODEL_H\n")
        f.write("#define SVM_MODEL_H\n\n")
        
        f.write("#include <stdint.h>\n\n")
        
        # Model parameters
        f.write(f"#define SVM_NUM_FEATURES {n_features}\n")
        f.write(f"#define SVM_NUM_SUPPORT_VECTORS {n_support_vectors}\n")
        f.write(f"#define SVM_GAMMA {gamma:.10f}f\n")
        f.write(f"#define SVM_BIAS {bias:.10f}f\n\n")
        
        # Support vector weights
        f.write("static const float svm_weights[SVM_NUM_SUPPORT_VECTORS] = {\n")
        for i, weight in enumerate(dual_coef):
            f.write(f"    {weight:.10f}f")
            if i < len(dual_coef) - 1:
                f.write(",")
            f.write("\n")
        f.write("};\n\n")
        
        # Support vectors
        f.write("static const float svm_support_vectors[SVM_NUM_SUPPORT_VECTORS][SVM_NUM_FEATURES] = {\n")
        for i in range(n_support_vectors):
            f.write("    {")
            for j in range(n_features):
                f.write(f"{support_vectors[i][j]:.10f}f")
                if j < n_features - 1:
                    f.write(", ")
            f.write("}")
            if i < n_support_vectors - 1:
                f.write(",")
            f.write("\n")
        f.write("};\n\n")
        
        # Feature normalization means
        f.write("static const float svm_feature_means[SVM_NUM_FEATURES] = {\n")
        for i, mean in enumerate(feature_means):
            f.write(f"    {mean:.10f}f")
            if i < len(feature_means) - 1:
                f.write(",")
            f.write("\n")
        f.write("};\n\n")
        
        # Feature normalization standard deviations
        f.write("static const float svm_feature_stds[SVM_NUM_FEATURES] = {\n")
        for i, std in enumerate(feature_stds):
            f.write(f"    {std:.10f}f")
            if i < len(feature_stds) - 1:
                f.write(",")
            f.write("\n")
        f.write("};\n\n")
        
        f.write("#endif // SVM_MODEL_H\n")
    
    print("Model exported successfully!")

def main():
    parser = argparse.ArgumentParser(description='Train SVM model for DDoS detection')
    parser.add_argument('--data', required=True, help='Path to CIC-DDoS2019 CSV file')
    parser.add_argument('--output', default='svm_model.h', help='Output C header file')
    parser.add_argument('--gamma', type=float, default=0.1, help='SVM gamma parameter')
    parser.add_argument('--C', type=float, default=1.0, help='SVM C parameter')
    parser.add_argument('--samples', type=int, default=100000, help='Maximum samples to use')
    
    args = parser.parse_args()
    
    # Load data
    print(f"Loading data from {args.data}")
    df = pd.read_csv(args.data)
    
    # Limit samples for faster training
    if len(df) > args.samples:
        df = df.sample(n=args.samples, random_state=42)
        print(f"Using {args.samples} samples for training")
    
    # Extract features and labels
    print("Extracting features...")
    X = extract_features(df)
    y = prepare_labels(df)
    
    print(f"Feature matrix shape: {X.shape}")
    print(f"Label distribution: {np.bincount(y)}")
    
    # Train model
    config = {
        'gamma': args.gamma,
        'C': args.C
    }
    
    svm, scaler = train_svm_model(X, y, config)
    
    # Export model
    export_model_to_c(svm, scaler, args.output)
    
    # Save sklearn model for comparison
    model_file = args.output.replace('.h', '.pkl')
    joblib.dump({'svm': svm, 'scaler': scaler}, model_file)
    print(f"Sklearn model saved to {model_file}")

if __name__ == '__main__':
    main()
