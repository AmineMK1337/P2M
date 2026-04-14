from pathlib import Path

import joblib
import numpy as np
import pandas as pd


MODEL_PATH = Path("deployments/models/pca_intrusion_detector.joblib")
TEST_CSV_PATH = Path("data/test/test.csv")


def normalize_name(name: str) -> str:
    return "".join(ch.lower() for ch in str(name) if ch.isalnum())


def anomaly_score(original: np.ndarray, reconstructed: np.ndarray) -> float:
    return float(np.sum((original - reconstructed) ** 2, axis=1)[0])


bundle = joblib.load(MODEL_PATH)
scaler = bundle["scaler"]
pca = bundle["pca"]
threshold = float(bundle["threshold"])
feature_columns = list(bundle.get("feature_columns", []))

if not feature_columns:
    raise ValueError("Model bundle missing 'feature_columns', cannot align input features.")

df = pd.read_csv(TEST_CSV_PATH)

print(f"Total test samples: {len(df)}")
print(f"Model path: {MODEL_PATH}")
print(f"Model expects {len(feature_columns)} features")
print(f"Threshold: {threshold:.6f}\n")

for i in range(min(15, len(df))):
    row = df.iloc[i]
    normalized_row = {normalize_name(col): row[col] for col in df.columns}
    aligned = {
        feature: normalized_row.get(normalize_name(feature), 0)
        for feature in feature_columns
    }

    x_df = pd.DataFrame([aligned], columns=feature_columns)
    x_df = x_df.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)

    x_scaled = scaler.transform(x_df)
    x_pca = pca.transform(x_scaled)
    x_reconstructed = pca.inverse_transform(x_pca)
    score = anomaly_score(x_scaled, x_reconstructed)

    is_benign = score < threshold
    label = "BENIGN" if is_benign else "ATTACK"

    eps = 1e-9
    if is_benign:
        benign_ratio = max(0.0, min(1.0, 1.0 - (score / (threshold + eps))))
        confidence = 0.5 + 0.5 * benign_ratio
    else:
        attack_ratio = max(0.0, min(1.0, (score - threshold) / (threshold + eps)))
        confidence = 0.5 + 0.5 * attack_ratio

    print(f"Row {i + 1}: {label} | score={score:.6f} | confidence={confidence:.3f}")
