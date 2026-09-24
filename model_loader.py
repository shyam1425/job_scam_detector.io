import os
from pathlib import Path

import joblib


def load_model():
    model_path = Path(os.getenv("MODEL_PATH", Path(__file__).with_name("job_classifier.pkl")))
    if not model_path.is_file():
        raise RuntimeError(
            f"ML model not found at {model_path}. "
            "Train it with: python train.py --dataset <dataset.csv>"
        )
    return joblib.load(model_path)
