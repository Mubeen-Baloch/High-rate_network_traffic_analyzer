import pandas as pd
import os

datasets = ['DrDoS_DNS.csv', 'Syn.csv', 'TFTP.csv']
dataset_dir = 'data/CSV-01-12/01-12'

print("Dataset sizes:")
for dataset in datasets:
    file_path = os.path.join(dataset_dir, dataset)
    if os.path.exists(file_path):
        df = pd.read_csv(file_path)
        print(f"{dataset}: {len(df):,} flows")
    else:
        print(f"{dataset}: File not found")
