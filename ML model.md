# ML Model

## Overview

This project uses a PCA-based anomaly detection model for network flow intrusion detection.

The core model is binary:
- 1 = benign
- -1 = attack (anomalous)

It does not natively predict attack family names (for example DDoS, PortScan, WebAttack). Attack-type labeling is handled by downstream logic in the classification layer.

## Data Source and Feature Preparation

Training is documented in:
- notebooks/cleaning-tsne-and-pca-intrusion-detection.ipynb

The notebook:
1. Loads improved CICIDS2017 daily CSV files and concatenates them.
2. Cleans the dataset (drops invalid rows, handles bad values, removes duplicates, etc.).
3. Removes metadata and leakage-prone fields such as IDs, IPs, ports, and timestamps.
4. Keeps flow-level numeric features for modeling.

## Training Strategy

The model is trained as an unsupervised detector using benign traffic only.

1. Create two groups:
- benign flows
- malicious flows

2. Sample benign data and split:
- 500000 benign flows for training
- 500000 benign flows for holdout evaluation pool

3. Build validation and test sets:
- append malicious flows to holdout pool
- split into validation and final test subsets

4. Hyperparameter search:
- try multiple scalers (Standard, Robust, Quantile, MinMax)
- PCA dimensionality is fixed to 64 in the current notebook loop

5. For each candidate:
- fit scaler on train benign
- fit PCA on scaled train benign
- compute validation reconstruction-error scores
- derive threshold from validation precision-recall curve using best F1 point
- compute AUROC and keep the configuration with highest validation AUROC

## Scoring and Decision Rule

Let x be a scaled input flow and x_hat its PCA reconstruction.

Anomaly score:
score = sum((x - x_hat)^2) over all features

Decision:
- if score < threshold: benign
- else: attack

This is implemented in src/models/pca_detector.py.

## Saved Model Artifact

The training notebook exports:
- deployments/models/pca_intrusion_detector.joblib

Saved bundle fields:
- scaler
- pca
- threshold
- n_components
- feature_columns

feature_columns preserves the expected feature order at inference time.

## Inference Path in Code

Model loading and prediction helpers are in:
- src/models/pca_detector.py

Main functions:
- anomaly_scores(original, transformed)
- pca_classifier(scaler, pca, threshold)
- load_model(model_path=None)

## Practical Limitations

1. Binary anomaly detector only:
- strong for anomaly flagging
- does not directly provide attack family class

2. Threshold sensitivity:
- performance depends on validation distribution and threshold calibration

3. Domain shift risk:
- if live traffic differs from training distribution, false positives or misses may increase

4. Feature consistency requirement:
- incoming flows must match trained feature schema and order

## Reproducibility

To regenerate the model artifact:
1. Open notebooks/cleaning-tsne-and-pca-intrusion-detection.ipynb
2. Run cells in order through the model export section
3. Confirm deployments/models/pca_intrusion_detector.joblib is produced
