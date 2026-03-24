from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
import sys

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from models.pca_detector import load_model  # noqa: E402


LABEL_CANDIDATES = ["Label", "label", "Attack", "attack", "Class", "class"]


def detect_label_column(columns: list[str]) -> str:
    for name in LABEL_CANDIDATES:
        if name in columns:
            return name
    raise ValueError(
        "No label column found. Expected one of: " + ", ".join(LABEL_CANDIDATES)
    )


def is_benign(label: str) -> bool:
    value = str(label).strip().lower()
    return value in {"benign", "normal"}


def iter_csv_files(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    return sorted(path.rglob("*.csv"))


def safe_div(numerator: float, denominator: float) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def evaluate_files(data_path: Path, chunksize: int = 50000, max_files: int | None = None) -> None:
    clf, bundle = load_model()
    feature_columns = list(bundle["feature_columns"])

    files = iter_csv_files(data_path)
    if max_files is not None:
        files = files[:max_files]

    if not files:
        raise FileNotFoundError(f"No CSV files found under: {data_path}")

    tp = fp = tn = fn = 0
    total_rows = 0

    per_attack_total = defaultdict(int)
    per_attack_detected = defaultdict(int)

    processed_files = 0

    for csv_file in files:
        header = pd.read_csv(csv_file, nrows=0)
        label_col = detect_label_column(list(header.columns))

        for chunk in pd.read_csv(csv_file, chunksize=chunksize):
            if label_col not in chunk.columns:
                continue

            y_labels = chunk[label_col].astype(str)
            y_true_attack = ~y_labels.map(is_benign)

            for col in feature_columns:
                if col not in chunk.columns:
                    chunk[col] = 0

            x = chunk[feature_columns].apply(pd.to_numeric, errors="coerce")
            x = x.replace([np.inf, -np.inf], np.nan).fillna(0)
            y_pred_attack = pd.Series(clf(x) == -1, index=chunk.index)

            tp += int((y_true_attack & y_pred_attack).sum())
            fp += int((~y_true_attack & y_pred_attack).sum())
            tn += int((~y_true_attack & ~y_pred_attack).sum())
            fn += int((y_true_attack & ~y_pred_attack).sum())
            total_rows += len(chunk)

            attack_rows = y_true_attack
            attack_types = y_labels[attack_rows]
            attack_preds = y_pred_attack[attack_rows]

            for attack_type, predicted_attack in zip(attack_types, attack_preds):
                attack_name = str(attack_type).strip()
                per_attack_total[attack_name] += 1
                if bool(predicted_attack):
                    per_attack_detected[attack_name] += 1

        processed_files += 1

    accuracy = safe_div(tp + tn, total_rows)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    f1 = safe_div(2 * precision * recall, precision + recall)

    print("=" * 70)
    print("PCA Intrusion Model Evaluation")
    print("=" * 70)
    print(f"Files evaluated : {processed_files}")
    print(f"Rows evaluated  : {total_rows}")
    print()
    print("Confusion matrix (attack detection)")
    print(f"TP={tp}  FP={fp}  TN={tn}  FN={fn}")
    print()
    print("Binary metrics")
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-score  : {f1:.4f}")
    print()

    if per_attack_total:
        print("Per attack-type detection rate")
        print("(This model is binary, so this means: rate predicted as ATTACK for each true type)")
        for attack_name in sorted(per_attack_total.keys()):
            detected = per_attack_detected[attack_name]
            total = per_attack_total[attack_name]
            rate = safe_div(detected, total)
            print(f"- {attack_name}: {rate:.4f} ({detected}/{total})")
    else:
        print("No attack rows found in provided data.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate saved PCA intrusion model on labeled CSV data.")
    parser.add_argument(
        "--data",
        type=Path,
        default=PROJECT_ROOT / "data" / "raw" / "CICIDS2017_improved" / "friday.csv",
        help="CSV file or directory containing labeled CSVs.",
    )
    parser.add_argument("--chunksize", type=int, default=50000, help="Rows per chunk while streaming CSVs.")
    parser.add_argument("--max-files", type=int, default=None, help="Optional cap on number of files when --data is a directory.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    evaluate_files(args.data, chunksize=args.chunksize, max_files=args.max_files)
