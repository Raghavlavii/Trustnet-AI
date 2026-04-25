"""Evaluate a trained TrustNet AI model on a labeled CSV dataset."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

from feature_engineering import build_vectorizer
from preprocess import normalize_label, preprocess_series


def _probabilities_from_model(model: Any, features: Any) -> list[float]:
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(features)
        classes = list(getattr(model, "classes_", [0, 1]))
        scam_index = classes.index(1) if 1 in classes else probabilities.shape[1] - 1
        return probabilities[:, scam_index].tolist()

    if hasattr(model, "decision_function"):
        scores = model.decision_function(features)
        return [1.0 / (1.0 + math.exp(-float(score))) for score in scores]

    raise RuntimeError("Model does not support probability inference.")


def evaluate_model(
    data_path: Path,
    model_path: Path,
    metrics_path: Path,
) -> dict[str, object]:
    """Load model, score a dataset, and write metrics JSON."""

    if not data_path.exists():
        raise FileNotFoundError(f"Evaluation dataset not found: {data_path}")
    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found: {model_path}")

    data = pd.read_csv(data_path).dropna(subset=["text", "label"]).copy()
    data["label"] = data["label"].map(normalize_label)
    data = data.dropna(subset=["label"])

    if data.empty:
        raise ValueError("No valid evaluation rows were found.")

    artifact = joblib.load(model_path)
    if isinstance(artifact, dict):
        model = artifact["classifier"]
        n_features = artifact.get("vectorizer_config", {}).get("n_features", 2**20)
    else:
        model = artifact
        n_features = 2**20

    vectorizer = build_vectorizer(n_features=n_features)
    texts = preprocess_series(data["text"])
    labels = data["label"].astype(int).to_numpy()
    features = vectorizer.transform(texts)
    probabilities = _probabilities_from_model(model, features)
    predictions = [1 if probability > 0.5 else 0 for probability in probabilities]

    metrics = {
        "rows": int(len(labels)),
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision_scam": round(
            float(precision_score(labels, predictions, pos_label=1, zero_division=0)),
            4,
        ),
        "recall_scam": round(
            float(recall_score(labels, predictions, pos_label=1, zero_division=0)),
            4,
        ),
        "f1_scam": round(
            float(f1_score(labels, predictions, pos_label=1, zero_division=0)),
            4,
        ),
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 4),
        "confusion_matrix": confusion_matrix(labels, predictions).tolist(),
        "classification_report": classification_report(
            labels,
            predictions,
            labels=[0, 1],
            target_names=["Safe", "Scam"],
            zero_division=0,
            output_dict=True,
        ),
    }

    metrics_path.parent.mkdir(parents=True, exist_ok=True)
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Evaluate TrustNet AI model.")
    parser.add_argument(
        "--data",
        type=Path,
        default=Path("ml/data/processed/trustnet_sms_test.csv"),
        help="Evaluation CSV with text,label columns.",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("ml/models/model.pkl"),
        help="Path to trained model artifact.",
    )
    parser.add_argument(
        "--metrics",
        type=Path,
        default=Path("ml/models/metrics.json"),
        help="Output path for evaluation metrics.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    summary = evaluate_model(args.data, args.model, args.metrics)
    print(json.dumps(summary, indent=2))

