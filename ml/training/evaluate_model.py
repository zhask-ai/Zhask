"""
Evaluate the trained IsolationForest model per-scenario.

Breaks down detection performance by anomaly type:
  - off_hours
  - bulk_extraction
  - shadow_endpoint

Usage (from repo root):
  python ml/training/evaluate_model.py
"""

import json
import pickle
import sys
from pathlib import Path

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import (
    extract_features_batch,
    features_to_matrix,
)

MODEL_PATH = REPO_ROOT / "ml" / "models" / "isolation_forest_v1.pkl"
SEED_DIR = REPO_ROOT / "ml" / "data" / "seed"


def load_model():
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model not found at {MODEL_PATH}. Run train_model.py first."
        )
    with open(MODEL_PATH, "rb") as f:
        return pickle.load(f)


def main():
    print("Loading model…")
    artifact = load_model()
    model = artifact["model"]
    scaler = artifact["scaler"]

    print("Loading seed data…")
    with open(SEED_DIR / "normal_events.json") as f:
        normal = json.load(f)
    with open(SEED_DIR / "anomaly_events.json") as f:
        anomalies = json.load(f)

    all_events = normal + anomalies
    feature_rows = extract_features_batch(all_events)

    labels = [r["label"] for r in feature_rows]
    X, y, event_ids = features_to_matrix(feature_rows)
    X_scaled = scaler.transform(X)

    scores = model.score_samples(X_scaled)
    preds = model.predict(X_scaled)
    pred_labels = (preds == -1).astype(int)

    print("\n=== Overall ===")
    _print_metrics(y, pred_labels)

    for scenario in ["off_hours", "bulk_extraction", "shadow_endpoint"]:
        mask = np.array([l == scenario for l in labels])
        if mask.sum() == 0:
            continue
        print(f"\n=== {scenario} (n={mask.sum()}) ===")
        _print_metrics(y[mask], pred_labels[mask])

    # Score distribution
    normal_scores = scores[y == 0]
    anomaly_scores = scores[y == 1]
    print(f"\n=== Score distribution ===")
    print(f"  Normal    mean={normal_scores.mean():.3f}  min={normal_scores.min():.3f}  max={normal_scores.max():.3f}")
    print(f"  Anomaly   mean={anomaly_scores.mean():.3f}  min={anomaly_scores.min():.3f}  max={anomaly_scores.max():.3f}")


def _print_metrics(y_true, y_pred):
    tp = int(((y_pred == 1) & (y_true == 1)).sum())
    fp = int(((y_pred == 1) & (y_true == 0)).sum())
    fn = int(((y_pred == 0) & (y_true == 1)).sum())
    tn = int(((y_pred == 0) & (y_true == 0)).sum())
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    print(f"  Precision={precision:.3f}  Recall={recall:.3f}  TP={tp} FP={fp} FN={fn} TN={tn}")


if __name__ == "__main__":
    main()
