"""
Train IsolationForest on seed data and log the run to MLflow.

Usage (from repo root):
  python ml/data/seed/generate_seed_data.py   # generate seed data first
  python ml/training/train_model.py

Outputs:
  ml/models/isolation_forest_v1.pkl   — pickled (model, scaler) tuple
  ml/models/feature_names.json        — ordered feature list
  MLflow run logged to ml/mlruns/
"""

import json
import os
import pickle
import sys
from pathlib import Path

import mlflow
import mlflow.sklearn
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Allow imports from repo root
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from ml.training.feature_engineering import (
    FEATURE_NAMES,
    extract_features_batch,
    features_to_matrix,
)

SEED_DIR = REPO_ROOT / "ml" / "data" / "seed"
MODEL_DIR = REPO_ROOT / "ml" / "models"
MLRUNS_DIR = REPO_ROOT / "ml" / "mlruns"

# IsolationForest hyperparameters
N_ESTIMATORS = 100
CONTAMINATION = 0.05  # ~5% of data expected to be anomalous
RANDOM_STATE = 42


def load_seed_data() -> tuple[list[dict], list[dict]]:
    normal_path = SEED_DIR / "normal_events.json"
    anomaly_path = SEED_DIR / "anomaly_events.json"

    if not normal_path.exists() or not anomaly_path.exists():
        raise FileNotFoundError(
            "Seed data not found. Run: python ml/data/seed/generate_seed_data.py"
        )

    with open(normal_path) as f:
        normal = json.load(f)
    with open(anomaly_path) as f:
        anomalies = json.load(f)

    return normal, anomalies


def main():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    mlflow.set_tracking_uri(f"sqlite:///{MLRUNS_DIR}/mlflow.db")
    mlflow.set_experiment("rfc_anomaly_detection")

    print("Loading seed data…")
    normal_events, anomaly_events = load_seed_data()
    print(f"  {len(normal_events)} normal | {len(anomaly_events)} anomaly events")

    # Feature extraction
    print("Extracting features…")
    all_events = normal_events + anomaly_events
    feature_rows = extract_features_batch(all_events)
    X, y, _ = features_to_matrix(feature_rows)

    # Train only on normal data (unsupervised — IsolationForest learns "normal")
    X_normal = X[y == 0]
    print(f"  Training on {len(X_normal)} normal samples…")

    scaler = StandardScaler()
    X_normal_scaled = scaler.fit_transform(X_normal)

    model = IsolationForest(
        n_estimators=N_ESTIMATORS,
        contamination=CONTAMINATION,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )

    with mlflow.start_run(run_name="isolation_forest_v1"):
        model.fit(X_normal_scaled)

        # Evaluate on full dataset (normal + anomalies)
        X_all_scaled = scaler.transform(X)
        scores = model.score_samples(X_all_scaled)
        preds = model.predict(X_all_scaled)  # -1 = anomaly, 1 = normal

        # Convert IsolationForest predictions to 0/1 labels
        pred_labels = (preds == -1).astype(int)

        tp = int(((pred_labels == 1) & (y == 1)).sum())
        fp = int(((pred_labels == 1) & (y == 0)).sum())
        fn = int(((pred_labels == 0) & (y == 1)).sum())
        tn = int(((pred_labels == 0) & (y == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fp_rate = fp / (fp + tn) if (fp + tn) > 0 else 0.0

        print(f"\n  Results:")
        print(f"    Precision:     {precision:.3f}")
        print(f"    Recall:        {recall:.3f}")
        print(f"    False pos rate:{fp_rate:.3f}")
        print(f"    TP={tp} FP={fp} FN={fn} TN={tn}")

        # Log to MLflow
        mlflow.log_params(
            {
                "n_estimators": N_ESTIMATORS,
                "contamination": CONTAMINATION,
                "random_state": RANDOM_STATE,
                "n_training_samples": len(X_normal),
                "n_features": len(FEATURE_NAMES),
            }
        )
        mlflow.log_metrics(
            {
                "precision": precision,
                "recall": recall,
                "fp_rate": fp_rate,
                "tp": tp,
                "fp": fp,
                "fn": fn,
                "tn": tn,
            }
        )
        mlflow.log_dict({"features": FEATURE_NAMES}, "feature_names.json")

        # Save model artifact
        model_path = MODEL_DIR / "isolation_forest_v1.pkl"
        with open(model_path, "wb") as f:
            pickle.dump({"model": model, "scaler": scaler}, f)

        feature_names_path = MODEL_DIR / "feature_names.json"
        with open(feature_names_path, "w") as f:
            json.dump(FEATURE_NAMES, f)

        mlflow.sklearn.log_model(model, "isolation_forest_model")
        print(f"\n  Model saved to {model_path}")
        print(f"  MLflow run: {mlflow.active_run().info.run_id}")


if __name__ == "__main__":
    main()
