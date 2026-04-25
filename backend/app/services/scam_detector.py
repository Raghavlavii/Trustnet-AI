"""ML model loading, text vectorization, scam probability, and trust scoring."""

from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

import joblib
from sklearn.feature_extraction.text import HashingVectorizer

from app.core.config import settings

URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
SPECIAL_CHARS_PATTERN = re.compile(r"[^a-z0-9\s]")
WHITESPACE_PATTERN = re.compile(r"\s+")

DEFAULT_VECTORIZER_CONFIG = {
    "n_features": 2**20,
    "alternate_sign": False,
    "ngram_range": (1, 2),
    "norm": "l2",
    "lowercase": False,
}

SCAM_KEYWORDS = (
    "urgent", "verify", "password", "otp", "bank", "account", "winner",
    "prize", "click", "limited", "suspended", "gift", "crypto", "loan", "refund",
)


def clean_text(text: str) -> str:
    normalized = str(text).lower()
    normalized = URL_PATTERN.sub(" ", normalized)
    normalized = SPECIAL_CHARS_PATTERN.sub(" ", normalized)
    normalized = WHITESPACE_PATTERN.sub(" ", normalized).strip()
    return normalized


def build_vectorizer(config: dict[str, Any] | None = None) -> HashingVectorizer:
    vectorizer_config = {**DEFAULT_VECTORIZER_CONFIG, **(config or {})}
    return HashingVectorizer(**vectorizer_config)


class ScamDetector:
    def __init__(self, model_path: Path | None = None) -> None:
        self.model_path = Path(model_path or settings.model_path)
        self.model: Any | None = None
        self.metadata: dict[str, Any] = {}
        self.vectorizer = build_vectorizer()
        self.model_loaded = False
        self.load_model()

    def load_model(self) -> None:
        if not self.model_path.exists():
            self.model_loaded = False
            return
        artifact = joblib.load(self.model_path)
        if isinstance(artifact, dict):
            self.model = artifact.get("classifier")
            self.vectorizer = build_vectorizer(artifact.get("vectorizer_config"))
            self.metadata = {
                "trained_rows": artifact.get("trained_rows"),
                "label_counts": artifact.get("label_counts"),
                "trained_at_utc": artifact.get("trained_at_utc"),
                "training_data": artifact.get("training_data"),
            }
        else:
            self.model = artifact
        self.model_loaded = self.model is not None

    def predict(self, text: str) -> dict[str, float | str]:
        if not text or not text.strip():
            raise ValueError("Text must not be empty.")
        if self.model_loaded:
            probability = self._predict_model_probability(text)
        else:
            probability = self._predict_heuristic_probability(text)
        probability = max(0.0, min(1.0, probability))
        trust_score = round((1.0 - probability) * 100.0, 2)
        label = "Scam" if probability > 0.5 else "Safe"
        return {"label": label, "trust_score": trust_score, "ml_scam_probability": round(probability, 4)}

    def _predict_model_probability(self, text: str) -> float:
        cleaned = clean_text(text)
        features = self.vectorizer.transform([cleaned])
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(features)[0]
            classes = list(getattr(self.model, "classes_", [0, 1]))
            idx = classes.index(1) if 1 in classes else len(probs) - 1
            return float(probs[idx])
        if hasattr(self.model, "decision_function"):
            score = float(self.model.decision_function(features)[0])
            return 1.0 / (1.0 + math.exp(-score))
        raise RuntimeError("Loaded model does not support probability inference.")

    def _predict_heuristic_probability(self, text: str) -> float:
        cleaned = clean_text(text)
        hits = sum(1 for kw in SCAM_KEYWORDS if kw in cleaned)
        has_url = bool(URL_PATTERN.search(text))
        has_money = any(t in cleaned for t in ("$", "rs", "usd", "inr"))
        pressure = any(t in cleaned for t in ("now", "immediately", "expires"))
        prob = 0.12 + (hits * 0.09)
        if has_url: prob += 0.16
        if has_money: prob += 0.08
        if pressure: prob += 0.08
        return min(prob, 0.92)


scam_detector = ScamDetector()
