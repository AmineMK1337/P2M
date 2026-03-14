# PCA Intrusion Detection Model — Usage Guide

This document explains how to load and use the pre-trained PCA anomaly detection model included in `deployments/models/pca_intrusion_detector.joblib`.

---

## How it works

The model reconstructs each network flow through a PCA transformation and measures the **reconstruction error** (sum of squared errors). Flows with high error are flagged as attacks.

- **Output `1`** → Benign traffic  
- **Output `-1`** → Attack / anomaly

---

## Requirements

Install all dependencies with:

```bash
pip install -r requirements.txt
```

> The model was trained with **scikit-learn 1.8.0**. Using a significantly different version may trigger a compatibility warning on load.

---

## Quick start

```python
import sys
sys.path.insert(0, "src")   # add project src to path

from models.pca_detector import load_model

# Load the trained model (scaler + PCA + threshold)
clf, bundle = load_model()

# clf expects a pandas DataFrame with the same feature columns used during training
predictions = clf(X)   # returns numpy array: 1 = benign, -1 = attack
```

### Checking required feature columns

```python
print(bundle["feature_columns"])   # list of column names in the expected order
```

Your input DataFrame must contain exactly these columns, in this order.

---

## Loading from a custom path

```python
from models.pca_detector import load_model

clf, bundle = load_model("path/to/your/pca_intrusion_detector.joblib")
```

---

## Bundle contents

| Key | Type | Description |
|---|---|---|
| `scaler` | sklearn transformer | Fitted scaler (RobustScaler) |
| `pca` | `sklearn.decomposition.PCA` | Fitted PCA (64 components) |
| `threshold` | `float` | Reconstruction error cut-off |
| `n_components` | `int` | Number of PCA components used |
| `feature_columns` | `list[str]` | Ordered list of expected input features |

---

## Full inference example

```python
import sys
import pandas as pd
sys.path.insert(0, "src")

from models.pca_detector import load_model

clf, bundle = load_model()

# Load your data (must have the same columns as training data)
df = pd.read_csv("your_network_flows.csv")
X = df[bundle["feature_columns"]]

predictions = clf(X)
df["prediction"] = predictions
df["label"] = df["prediction"].map({1: "BENIGN", -1: "ATTACK"})

print(df["label"].value_counts())
```

---

## Re-training

To retrain the model, run all cells in:

```
notebooks/cleaning-tsne-and-pca-intrusion-detection.ipynb
```

The save-model cell near the end of the notebook will overwrite `deployments/models/pca_intrusion_detector.joblib` automatically.

> **Note:** The raw datasets are not included in this repository due to their size (~37 GB).  
> Download them from the [Improved CIC-IDS dataset page](https://intrusion-detection.distrinet-research.be/CNS2022/Dataset_Download.html) and place them under `data/raw/`.
