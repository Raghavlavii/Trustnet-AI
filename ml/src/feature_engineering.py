"""Feature extraction helpers for scalable text classification."""

from __future__ import annotations

from typing import Iterable

from scipy.sparse import csr_matrix
from sklearn.feature_extraction.text import HashingVectorizer


VECTORIZER_CONFIG = {
    "n_features": 2**20,
    "alternate_sign": False,
    "ngram_range": (1, 2),
    "norm": "l2",
    "lowercase": False,
}


def build_vectorizer(n_features: int = 2**20) -> HashingVectorizer:
    """Create a stateless HashingVectorizer suitable for chunk processing."""

    config = {**VECTORIZER_CONFIG, "n_features": n_features}
    return HashingVectorizer(**config)


def vectorize_texts(
    texts: Iterable[str], vectorizer: HashingVectorizer | None = None
) -> csr_matrix:
    """Transform cleaned texts into sparse ML features."""

    active_vectorizer = vectorizer or build_vectorizer()
    return active_vectorizer.transform(texts)

