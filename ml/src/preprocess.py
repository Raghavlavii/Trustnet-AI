"""Text and label preprocessing utilities for TrustNet AI training."""

from __future__ import annotations

import re
from typing import Any

import pandas as pd


URL_PATTERN = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
SPECIAL_CHARS_PATTERN = re.compile(r"[^a-z0-9\s]")
WHITESPACE_PATTERN = re.compile(r"\s+")

SCAM_LABELS = {"1", "scam", "fraud", "phishing", "malicious", "spam"}
SAFE_LABELS = {"0", "safe", "legit", "legitimate", "ham", "normal"}


def clean_text(text: str) -> str:
    """Lowercase text, remove URLs and special characters, and normalize spaces."""

    normalized = str(text).lower()
    normalized = URL_PATTERN.sub(" ", normalized)
    normalized = SPECIAL_CHARS_PATTERN.sub(" ", normalized)
    normalized = WHITESPACE_PATTERN.sub(" ", normalized).strip()
    return normalized


def preprocess_series(series: pd.Series) -> pd.Series:
    """Apply text cleaning to a pandas Series without loading all data at once."""

    return series.fillna("").astype(str).map(clean_text)


def normalize_label(label: Any) -> int | None:
    """Map supported labels to 1 for Scam and 0 for Safe."""

    if pd.isna(label):
        return None

    value = str(label).strip().lower()
    if value in SCAM_LABELS:
        return 1
    if value in SAFE_LABELS:
        return 0
    return None

