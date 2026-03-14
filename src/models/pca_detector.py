import numpy as np
import joblib
from pathlib import Path


def anomaly_scores(original, transformed):
    """Sum of squared reconstruction errors per sample."""
    return np.sum((original - transformed) ** 2, axis=1)


def pca_classifier(scaler, pca, threshold):
    """Return a prediction function that labels samples as 1 (benign) or -1 (attack)."""
    def clf(X):
        x = scaler.transform(X)
        X_pca = pca.transform(x)
        X_pca_inv = pca.inverse_transform(X_pca)
        score = anomaly_scores(x, X_pca_inv)
        return np.array([1 if s < threshold else -1 for s in score])
    return clf


def load_model(model_path=None):
    """
    Load the saved model bundle and return a ready-to-use classifier.

    Parameters
    ----------
    model_path : str or Path, optional
        Path to the .joblib file. Defaults to
        <project_root>/deployments/models/pca_intrusion_detector.joblib

    Returns
    -------
    clf : callable
        Prediction function: clf(X) -> np.ndarray of 1 (benign) / -1 (attack)
    bundle : dict
        Full bundle with keys: scaler, pca, threshold, n_components, feature_columns
    """
    if model_path is None:
        model_path = Path(__file__).resolve().parents[2] / "deployments" / "models" / "pca_intrusion_detector.joblib"
    bundle = joblib.load(model_path)
    clf = pca_classifier(bundle["scaler"], bundle["pca"], bundle["threshold"])
    return clf, bundle
