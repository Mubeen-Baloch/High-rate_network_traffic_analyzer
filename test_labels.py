#!/usr/bin/env python3

import pandas as pd

# Load the test dataset
df = pd.read_csv('test_small.csv', nrows=10)

print("Label distribution:")
print(df[' Label'].value_counts())

print("\nSample labels:")
for i, label in enumerate(df[' Label'].head()):
    print(f"Row {i}: '{label}' -> {1 if label != 'BENIGN' else 0}")

