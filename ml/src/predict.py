"""Standalone CLI prediction helper for the trained TrustNet AI model."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Any

import joblib

from feature_engineering import build_vectorizer
from preprocess import clean_text


def _probability_from_model(model: Any, features: Any) -> float:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)[0]
        classes = list(getattr(model, "classes_", [0, 1]))
        scam_index = classes.index(1) if 1 in classes else len(probabilities) - 1
        return float(probabilities[scam_index])

    if hasattr(model, "decision_function"):
        score = float(model.decision_function(features)[0])
        return 1.0 / (1.0 + math.exp(-score))

    raise RuntimeError("Model does not support probability inference.")


def predict_text(text: str, model_path: Path = Path("ml/models/model.pkl")) -> dict[str, float | str]:
    """Load model.pkl and predict one message from the command line."""

    artifact = joblib.load(model_path)
    if isinstance(artifact, dict):
        model = artifact["classifier"]
        vectorizer = build_vectorizer(
            n_features=artifact.get("vectorizer_config", {}).get("n_features", 2**20)
        )
    else:
        model = artifact
        vectorizer = build_vectorizer()

    features = vectorizer.transform([clean_text(text)])
    probability = max(0.0, min(1.0, _probability_from_model(model, features)))
    label = "Scam" if probability > 0.5 else "Safe"
    return {
        "label": label,
        "trust_score": round((1.0 - probability) * 100.0, 2),
        "ml_scam_probability": round(probability, 4),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Predict scam probability.")
    parser.add_argument("--text", required=True, help="Message to verify.")
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("ml/models/model.pkl"),
        help="Path to trained model artifact.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    print(predict_text(args.text, args.model))

