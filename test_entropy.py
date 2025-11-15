#!/usr/bin/env python3

import pandas as pd
import numpy as np
from collections import Counter
import math

def calculate_entropy(ip_list):
    """Calculate entropy of IP addresses"""
    if not ip_list:
        return 0.0
    
    # Count occurrences
    counts = Counter(ip_list)
    total = len(ip_list)
    
    # Calculate entropy
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    
    return entropy

# Load dataset sample
print("Loading dataset sample...")
df = pd.read_csv('data/CSV-01-12/01-12/DrDoS_DNS.csv', nrows=10000)

# Extract source IPs for attack and benign flows
attacks = df[df[' Label'] == 'DrDoS_DNS']
benign = df[df[' Label'] == 'BENIGN']

print(f"Attack flows: {len(attacks)}")
print(f"Benign flows: {len(benign)}")

# Calculate entropy for attack flows
attack_ips = attacks[' Source IP'].tolist()
attack_entropy = calculate_entropy(attack_ips)
print(f"Attack entropy: {attack_entropy:.4f}")

# Calculate entropy for benign flows  
benign_ips = benign[' Source IP'].tolist()
benign_entropy = calculate_entropy(benign_ips)
print(f"Benign entropy: {benign_entropy:.4f}")

# Check unique IP counts
print(f"Unique attack IPs: {len(set(attack_ips))}")
print(f"Unique benign IPs: {len(set(benign_ips))}")

# Sample some IPs
print(f"\nSample attack IPs: {attack_ips[:10]}")
print(f"Sample benign IPs: {benign_ips[:10]}")

print(f"\nCurrent entropy threshold: 3.0")
print(f"Attack entropy < threshold: {attack_entropy < 3.0}")
print(f"Benign entropy < threshold: {benign_entropy < 3.0}")

