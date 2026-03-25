from __future__ import annotations

from pathlib import Path
import warnings

import joblib
import numpy as np
import pandas as pd
import pytest


# This model artifact was trained with sklearn 1.6.1 and is validated here under
# the current environment. Keep tests signal-focused by filtering expected warnings.
pytestmark = [
    pytest.mark.filterwarnings("ignore:Trying to unpickle estimator.*:sklearn.exceptions.InconsistentVersionWarning"),
    pytest.mark.filterwarnings("ignore:Trying to unpickle estimator.*:UserWarning"),
]


MODEL_PATH = Path(__file__).resolve().parents[2] / "deployments" / "models" / "model.pkl"
TEST_CSV_PATH = Path(__file__).resolve().parents[2] / "data" / "test" / "test.csv"


def _normalize_name(name: str) -> str:
    return "".join(ch.lower() for ch in str(name) if ch.isalnum())


def load_model():
    # Some sklearn versions may emit compatibility warnings while loading.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Trying to unpickle estimator.*")
        return joblib.load(MODEL_PATH)


def test_model_pkl_exists_and_loads() -> None:
    assert MODEL_PATH.exists(), f"Model file not found: {MODEL_PATH}"

    model = load_model()

    # Basic API checks for sklearn-like estimators
    assert hasattr(model, "predict"), "Loaded model does not expose predict()"


def test_model_pkl_predict_single_sample() -> None:
    model = load_model()

    # Build a valid input shape from model metadata.
    n_features = getattr(model, "n_features_in_", None)
    if n_features is None and hasattr(model, "feature_names_in_"):
        n_features = len(model.feature_names_in_)

    assert n_features is not None, "Could not infer required number of input features"

    if hasattr(model, "feature_names_in_"):
        feature_names = list(model.feature_names_in_)
        x = pd.DataFrame(np.zeros((1, len(feature_names)), dtype=float), columns=feature_names)
    else:
        x = np.zeros((1, int(n_features)), dtype=float)

    y = model.predict(x)

    assert y.shape == (1,), f"Expected prediction shape (1,), got {y.shape}"
    # IsolationForest convention: 1=inlier, -1=outlier.
    assert y[0] in (-1, 1), f"Unexpected class label: {y[0]}"


def test_model_pkl_predict_from_test_csv() -> None:
    model = load_model()
    assert TEST_CSV_PATH.exists(), f"Test CSV not found: {TEST_CSV_PATH}"

    df = pd.read_csv(TEST_CSV_PATH, nrows=1)
    assert len(df) == 1, "Expected at least one row in data/test/test.csv"

    if hasattr(model, "feature_names_in_"):
        feature_names = list(model.feature_names_in_)
        row = df.iloc[0]

        normalized_row = {_normalize_name(col): row[col] for col in df.columns}
        aligned = {}
        for feature in feature_names:
            key = _normalize_name(feature)
            aligned[feature] = normalized_row.get(key, 0)

        x = pd.DataFrame([aligned], columns=feature_names)
        x = x.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan).fillna(0)
    else:
        n_features = getattr(model, "n_features_in_", None)
        assert n_features is not None, "Could not infer required number of input features"
        x = np.zeros((1, int(n_features)), dtype=float)

    y = model.predict(x)
    assert y.shape == (1,), f"Expected prediction shape (1,), got {y.shape}"
    assert y[0] in (-1, 1), f"Unexpected class label: {y[0]}"
