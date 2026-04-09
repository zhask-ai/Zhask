"""Load trained IsolationForest model and scaler from disk."""

import logging
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


def load_model(model_path: str) -> tuple:
    """
    Load (model, scaler) tuple from the pickle file produced by train_model.py.
    Raises FileNotFoundError if the model hasn't been trained yet.
    """
    path = Path(model_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Model not found at {path}. "
            "Run ml/training/train_model.py to train the model first."
        )
    with open(path, "rb") as f:
        artifact = pickle.load(f)

    if isinstance(artifact, tuple):
        model, scaler = artifact
    else:
        model = artifact["model"]
        scaler = artifact["scaler"]
    logger.info("Loaded IsolationForest model from %s", path)
    return model, scaler
