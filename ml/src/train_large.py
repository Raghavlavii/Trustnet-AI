"""Incremental training script for large CSV datasets.

Expected dataset format:
text,label
Your message here,Scam
Another normal message,Safe
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.linear_model import SGDClassifier

from feature_engineering import VECTORIZER_CONFIG, build_vectorizer
from preprocess import normalize_label, preprocess_series


CLASSES = np.array([0, 1])


def train_large_dataset(
    data_path: Path,
    model_path: Path,
    chunksize: int = 50000,
    n_features: int = 2**20,
) -> dict[str, int]:
    """Train SGDClassifier incrementally over CSV chunks and save model.pkl."""

    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found: {data_path}")

    classifier = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=1e-5,
        random_state=42,
        max_iter=1,
        tol=None,
    )
    vectorizer = build_vectorizer(n_features=n_features)

    total_rows = 0
    label_counts = {0: 0, 1: 0}

    for chunk_number, chunk in enumerate(
        pd.read_csv(data_path, chunksize=chunksize), start=1
    ):
        required_columns = {"text", "label"}
        missing_columns = required_columns.difference(chunk.columns)
        if missing_columns:
            raise ValueError(
                "Dataset must contain text,label columns. "
                f"Missing: {', '.join(sorted(missing_columns))}"
            )

        chunk = chunk.dropna(subset=["text", "label"]).copy()
        chunk["label"] = chunk["label"].map(normalize_label)
        chunk = chunk.dropna(subset=["label"])

        if chunk.empty:
            print(f"Chunk {chunk_number}: skipped because no valid rows remained.")
            continue

        texts = preprocess_series(chunk["text"])
        labels = chunk["label"].astype(int).to_numpy()
        features = vectorizer.transform(texts)

        classifier.partial_fit(features, labels, classes=CLASSES)

        total_rows += len(labels)
        label_counts[0] += int((labels == 0).sum())
        label_counts[1] += int((labels == 1).sum())
        print(
            f"Chunk {chunk_number}: trained on {len(labels)} rows "
            f"(total={total_rows})"
        )

    if total_rows == 0:
        raise ValueError("No valid training rows were found.")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "classifier": classifier,
        "vectorizer_config": {**VECTORIZER_CONFIG, "n_features": n_features},
        "label_mapping": {"Safe": 0, "Scam": 1},
        "trained_rows": total_rows,
        "label_counts": label_counts,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "training_data": str(data_path),
    }
    joblib.dump(artifact, model_path)

    return {
        "trained_rows": total_rows,
        "safe_rows": label_counts[0],
        "scam_rows": label_counts[1],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train TrustNet AI on a large CSV.")
    parser.add_argument(
        "--data",
        type=Path,
        required=True,
        help="Path to CSV dataset with text,label columns.",
    )
    parser.add_argument(
        "--model",
        type=Path,
        default=Path("ml/models/model.pkl"),
        help="Output path for the trained joblib model artifact.",
    )
    parser.add_argument(
        "--chunksize",
        type=int,
        default=50000,
        help="Rows to process per pandas chunk.",
    )
    parser.add_argument(
        "--n-features",
        type=int,
        default=2**20,
        help="HashingVectorizer feature dimension.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    summary = train_large_dataset(
        data_path=args.data,
        model_path=args.model,
        chunksize=args.chunksize,
        n_features=args.n_features,
    )
    print(f"Saved model to {args.model}")
    print(summary)
