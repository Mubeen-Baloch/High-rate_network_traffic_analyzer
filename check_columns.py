import pandas as pd

df = pd.read_csv('data/CSV-01-12/01-12/DrDoS_DNS.csv', nrows=1)
print("Columns with spaces:")
for col in df.columns:
    if ' ' in col:
        print(f'  "{col}"')
