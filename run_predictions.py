import pandas as pd
import joblib
import numpy as np
import warnings
warnings.filterwarnings('ignore')

model = joblib.load('deployments/models/model.pkl')
df = pd.read_csv('data/test/test.csv')

def normalize_name(n):
    return ''.join(c.lower() for c in str(n) if c.isalnum())

features = list(model.feature_names_in_)
print(f'Total test samples: {len(df)}')
print(f'Model expects {len(features)} features\n')

for i in range(min(15, len(df))):
    row = df.iloc[i]
    norm_row = {normalize_name(c): row[c] for c in df.columns}
    aligned = {f: norm_row.get(normalize_name(f), 0) for f in features}
    X = pd.DataFrame([aligned], columns=features)
    X = X.apply(pd.to_numeric, errors='coerce').replace([np.inf, -np.inf], np.nan).fillna(0)
    pred = model.predict(X)[0]
    label = 'INLIER' if pred == 1 else 'OUTLIER'
    print(f'Row {i+1}: {label}')
