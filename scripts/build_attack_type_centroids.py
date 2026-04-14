from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
from typing import Iterable

import joblib
import numpy as np
import pandas as pd


LABEL_CANDIDATES = ["Label", "label", "Attack", "attack", "Class", "class"]


def canonical_attack_type(raw_label: str) -> str:
    text = str(raw_label).strip()
    lowered = text.lower()

    if not text or lowered in {"benign", "normal", "inlier"}:
        return "BENIGN"
    if "attempted" in lowered:
        return "BENIGN"

    if "portscan" in lowered or "port scan" in lowered:
        return "PortScan"
    if any(token in lowered for token in ["ddos", "dos ", "dos-", "hulk", "slowloris", "slowhttptest", "goldeneye"]):
        return "DDoS"
    if any(token in lowered for token in ["brute", "patator", "ssh-bruteforce", "ftp-bruteforce", "ssh brute", "ftp brute"]):
        return "BruteForce"
    if any(token in lowered for token in ["web attack", "xss", "sql injection", "sqli"]):
        return "WebAttack"
    if "bot" in lowered:
        return "Botnet"
    if "infiltration" in lowered:
        return "Infiltration"
    if "heartbleed" in lowered:
        return "Heartbleed"

    return text


def detect_label_column(columns: Iterable[str]) -> str | None:
    normalized = {str(col).strip(): col for col in columns}
    for candidate in LABEL_CANDIDATES:
        if candidate in normalized:
            return normalized[candidate]
    return None


def align_features(chunk: pd.DataFrame, feature_columns: list[str]) -> pd.DataFrame:
    aligned = pd.DataFrame(index=chunk.index)
    for feature in feature_columns:
        if feature in chunk.columns:
            aligned[feature] = pd.to_numeric(chunk[feature], errors="coerce")
        else:
            aligned[feature] = 0.0

    aligned = aligned.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return aligned


def build_centroids(
    model_path: Path,
    data_dirs: list[Path],
    chunksize: int,
    max_rows_per_file: int | None,
) -> dict[str, list[float]]:
    bundle = joblib.load(model_path)
    scaler = bundle["scaler"]
    feature_columns = list(bundle["feature_columns"])

    sums: dict[str, np.ndarray] = {}
    counts: defaultdict[str, int] = defaultdict(int)

    files: list[Path] = []
    for data_dir in data_dirs:
        if data_dir.exists():
            files.extend(sorted(data_dir.glob("*.csv")))

    if not files:
        raise FileNotFoundError(f"No CSV files found in: {data_dirs}")

    print(f"[centroids] Processing {len(files)} CSV file(s)...")

    for csv_file in files:
        print(f"[centroids] Reading {csv_file}")
        rows_seen = 0
        for chunk in pd.read_csv(csv_file, chunksize=chunksize, low_memory=False):
            if max_rows_per_file is not None and rows_seen >= max_rows_per_file:
                break

            if max_rows_per_file is not None:
                remaining = max_rows_per_file - rows_seen
                if remaining <= 0:
                    break
                if len(chunk) > remaining:
                    chunk = chunk.iloc[:remaining].copy()

            chunk.columns = [str(col).strip() for col in chunk.columns]
            label_col = detect_label_column(chunk.columns)
            if label_col is None:
                rows_seen += len(chunk)
                continue

            labels = chunk[label_col].astype(str).map(canonical_attack_type)
            aligned = align_features(chunk, feature_columns)
            scaled = scaler.transform(aligned)

            attack_mask = labels != "BENIGN"
            if not attack_mask.any():
                continue

            for attack_type in labels[attack_mask].unique():
                mask = labels == attack_type
                vectors = scaled[mask.to_numpy()]
                if vectors.size == 0:
                    continue

                if attack_type not in sums:
                    sums[attack_type] = np.zeros(vectors.shape[1], dtype=float)
                sums[attack_type] += vectors.sum(axis=0)
                counts[attack_type] += int(mask.sum())

            rows_seen += len(chunk)

    centroids: dict[str, list[float]] = {}
    for attack_type, total in sums.items():
        count = counts[attack_type]
        if count <= 0:
            continue
        centroids[attack_type] = (total / count).astype(float).tolist()

    if not centroids:
        raise RuntimeError("No non-benign labeled rows found. Could not build centroids.")

    bundle["attack_type_centroids"] = centroids
    bundle["attack_classes"] = sorted(centroids.keys())
    bundle["attack_type_source"] = "nearest_centroid_scaled_space"
    bundle["attack_type_feature_space"] = "scaled"

    backup_path = model_path.with_suffix(model_path.suffix + ".bak")
    if not backup_path.exists():
        joblib.dump(joblib.load(model_path), backup_path)
        print(f"[centroids] Backup written to {backup_path}")

    joblib.dump(bundle, model_path)
    print(f"[centroids] Updated model bundle written to {model_path}")
    print(f"[centroids] Attack types: {', '.join(sorted(centroids.keys()))}")

    sidecar_path = model_path.with_suffix(".attack_type_centroids.json")
    sidecar_payload = {
        "attack_type_centroids": centroids,
        "attack_classes": sorted(centroids.keys()),
        "attack_type_source": "nearest_centroid_scaled_space",
        "attack_type_feature_space": "scaled",
    }
    sidecar_path.write_text(json.dumps(sidecar_payload, indent=2), encoding="utf-8")
    print(f"[centroids] Sidecar written to {sidecar_path}")

    return centroids


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build and inject attack-type centroids into PCA intrusion model bundle.")
    parser.add_argument(
        "--model",
        default="deployments/models/pca_intrusion_detector.joblib",
        help="Path to pca_intrusion_detector.joblib",
    )
    parser.add_argument(
        "--data-dir",
        action="append",
        default=None,
        help="Directory containing labeled CSV files. Can be passed multiple times.",
    )
    parser.add_argument("--chunksize", type=int, default=20000, help="CSV chunk size for incremental processing.")
    parser.add_argument(
        "--max-rows-per-file",
        type=int,
        default=None,
        help="Optional cap on rows processed per file for faster centroid generation.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    model_path = Path(args.model)
    default_dirs = [
        "data/raw/CICIDS2017_improved",
        "data/raw/CSECICIDS2018_improved",
    ]
    selected_dirs = args.data_dir if args.data_dir else default_dirs
    data_dirs = [Path(path) for path in selected_dirs]

    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")

    centroids = build_centroids(
        model_path=model_path,
        data_dirs=data_dirs,
        chunksize=args.chunksize,
        max_rows_per_file=args.max_rows_per_file,
    )
    print(f"[centroids] Built {len(centroids)} attack centroid(s).")


if __name__ == "__main__":
    main()
