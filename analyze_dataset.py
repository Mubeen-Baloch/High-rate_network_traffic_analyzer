#!/usr/bin/env python3

import pandas as pd
import numpy as np

# Load dataset sample
print("Loading dataset sample...")
df = pd.read_csv('data/CSV-01-12/01-12/DrDoS_DNS.csv', nrows=10000)

print("Label distribution:")
print(df[' Label'].value_counts())

print("\nAttack characteristics:")
attacks = df[df[' Label'] == 'DrDoS_DNS']
print(f'Attack flows: {len(attacks)}')
print(f'Avg forward packets: {attacks[" Total Fwd Packets"].mean():.2f}')
print(f'Avg backward packets: {attacks[" Total Backward Packets"].mean():.2f}')
print(f'Avg flow duration: {attacks[" Flow Duration"].mean():.2f}')
print(f'Avg bytes/sec: {attacks["Flow Bytes/s"].mean():.2f}')

print("\nBenign characteristics:")
benign = df[df[' Label'] == 'BENIGN']
print(f'Benign flows: {len(benign)}')
print(f'Avg forward packets: {benign[" Total Fwd Packets"].mean():.2f}')
print(f'Avg backward packets: {benign[" Total Backward Packets"].mean():.2f}')
print(f'Avg flow duration: {benign[" Flow Duration"].mean():.2f}')
print(f'Avg bytes/sec: {benign["Flow Bytes/s"].mean():.2f}')

print("\nKey differences:")
print(f"Attack flows have {attacks[' Total Fwd Packets'].mean() / benign[' Total Fwd Packets'].mean():.2f}x more forward packets")
print(f"Attack flows have {attacks[' Total Backward Packets'].mean() / benign[' Total Backward Packets'].mean():.2f}x more backward packets")
print(f"Attack flows are {attacks[' Flow Duration'].mean() / benign[' Flow Duration'].mean():.2f}x longer duration")

