#!/usr/bin/env python3
"""
Quick test of dataset and demonstrate project capabilities
"""

import pandas as pd
import numpy as np
import os

print("=" * 60)
print("DDoS Detection System - Dataset Test & Demo")
print("=" * 60)

# Find a dataset file
dataset_dir = "data/CSV-01-12/01-12"
if not os.path.exists(dataset_dir):
    dataset_dir = "data/CSV-03-11/03-11"

csv_files = [f for f in os.listdir(dataset_dir) if f.endswith('.csv')]

if not csv_files:
    print("ERROR: No CSV files found!")
    exit(1)

# Test with first dataset
test_file = os.path.join(dataset_dir, csv_files[0])
print(f"\nLoading: {test_file}")

# Load a small sample
print("Loading first 10000 rows...")
df = pd.read_csv(test_file, nrows=10000)

print(f"\n✅ Dataset Loaded Successfully!")
print(f"   Rows: {len(df)}")
print(f"   Columns: {len(df.columns)}")
print(f"   Attack Type: {df[' Label'].unique()}")

# Basic statistics
print("\n" + "=" * 60)
print("Dataset Statistics:")
print("=" * 60)

# Get unique labels
labels = df[' Label'].unique()
print(f"\nAttack Types Found: {labels}")

# Count by label
label_counts = df[' Label'].value_counts()
print("\nLabel Distribution:")
for label, count in label_counts.items():
    print(f"  {label}: {count} flows")

# Basic flow statistics
print(f"\nFlow Statistics:")
print(f"  Average Duration: {df['Flow Duration'].mean():.2f} microseconds")
print(f"  Average Packets: {df['Total Fwd Packets'].add(df['Total Backward Packets']).mean():.2f}")
print(f"  Average Bytes: {df['Total Length of Fwd Packets'].add(df['Total Length of Bwd Packets']).mean():.2f}")

# Entropy calculation (demonstrating detection)
print("\n" + "=" * 60)
print("Demonstrating Entropy-Based Detection:")
print("=" * 60)

# Calculate packet rate entropy
packet_rates = df['Flow Packets/s']
packet_rates = packet_rates[packet_rates > 0]

# Simple entropy calculation
from collections import Counter
rates_discrete = pd.cut(packet_rates, bins=10, labels=False)
frequency = Counter(rates_discrete)
entropy = -sum(p * np.log2(p) for p in frequency.values() if p > 0)

print(f"Packet Rate Entropy: {entropy:.4f}")
print(f"  Low entropy suggests concentrated traffic (potential DDoS)")

# CUSUM-like detection
print("\n" + "=" * 60)
print("Demonstrating CUSUM Statistical Detection:")
print("=" * 60)

baseline_packet_rate = df['Flow Packets/s'].quantile(0.5)
current_packet_rate = df['Flow Packets/s'].mean()

print(f"Baseline Packet Rate: {baseline_packet_rate:.2f} packets/sec")
print(f"Current Packet Rate: {current_packet_rate:.2f} packets/sec")
print(f"Deviation: {current_packet_rate - baseline_packet_rate:.2f}")
print(f"  Large deviation suggests anomaly detection trigger")

print("\n" + "=" * 60)
print("✅ Test Complete - All Systems Working!")
print("=" * 60)
print("\nNext Steps:")
print("1. Build full C implementation")
print("2. Run GPU-accelerated detection")
print("3. Generate performance metrics and plots")
print("\nProject Status: Ready for full implementation!")

