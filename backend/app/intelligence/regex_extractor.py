"""Regex and pattern-based intelligence extraction from scam messages."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_PHONE = re.compile(
    r"""
    (?:
        (?:\+?\d{1,3}[\s\-.])?          # optional country code
        (?:\(?\d{2,4}\)?[\s\-.])?       # optional area code
        \d{3,5}[\s\-.]                  # exchange
        \d{3,5}                         # subscriber
    )
    """,
    re.VERBOSE,
)

_EMAIL = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"
)

_URL = re.compile(
    r"https?://[^\s<>\"'()]+|www\.[^\s<>\"'()]+"
)

_UPI = re.compile(
    r"[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}"
)

_AMOUNT_INR = re.compile(
    r"(?:rs\.?|inr|₹)\s*[\d,]+(?:\.\d{1,2})?",
    re.IGNORECASE,
)
_AMOUNT_USD = re.compile(
    r"\$\s*[\d,]+(?:\.\d{1,2})?|\bUSD\s*[\d,]+",
    re.IGNORECASE,
)
_AMOUNT_GENERIC = re.compile(
    r"\b\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?\b"   # e.g. 1,50,000
)

_CARD_PARTIAL = re.compile(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b")

_CRYPTO_WALLET = re.compile(
    r"\b(?:0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-Z0-9]{6,87})\b"
)

_AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
_PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")

# Scam indicator keywords grouped by type
_SCAM_SIGNALS: dict[str, list[str]] = {
    "urgency": ["urgent", "immediately", "now", "expires", "limited time", "today only"],
    "credential_request": ["password", "otp", "pin", "login", "verify", "kyc"],
    "financial_bait": ["prize", "winner", "lottery", "reward", "cashback", "refund"],
    "payment_pressure": ["pay", "deposit", "fee", "transfer", "send money", "wallet"],
    "threat": ["suspended", "blocked", "legal", "arrest", "notice", "action"],
    "impersonation": ["bank", "government", "rbi", "irs", "police", "courier", "amazon"],
    "link_lure": ["click here", "visit", "link", "http", "www"],
}

# Scam type classifier patterns
_SCAM_TYPES: dict[str, list[str]] = {
    "phishing": ["password", "login", "verify account", "credentials", "otp"],
    "lottery_fraud": ["winner", "prize", "lottery", "selected", "claim"],
    "banking_fraud": ["bank", "account suspended", "kyc", "rbi", "card blocked"],
    "job_scam": ["job offer", "work from home", "salary", "joining fee", "hiring"],
    "investment_scam": ["crypto", "investment", "double", "profit", "returns", "trading"],
    "delivery_scam": ["parcel", "courier", "package", "shipment", "delivery fee"],
    "refund_scam": ["refund", "cashback", "process", "release amount", "pending"],
    "romance_scam": ["love", "relationship", "meet", "together", "gift money"],
    "tech_support": ["device infected", "virus", "support", "call now", "technician"],
}


@dataclass
class RegexIntelligence:
    """Container for all regex-extracted intelligence."""

    phone_numbers: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    payment_details: list[str] = field(default_factory=list)
    crypto_wallets: list[str] = field(default_factory=list)
    amounts: list[str] = field(default_factory=list)
    aadhaar_numbers: list[str] = field(default_factory=list)
    pan_numbers: list[str] = field(default_factory=list)
    scam_indicators: list[str] = field(default_factory=list)
    scam_type: str = "unknown"
    risk_level: str = "low"

    def to_dict(self) -> dict[str, Any]:
        return {
            "phone_numbers": self.phone_numbers,
            "email_addresses": self.email_addresses,
            "urls": self.urls,
            "upi_ids": self.upi_ids,
            "payment_details": self.payment_details,
            "crypto_wallets": self.crypto_wallets,
            "amounts": self.amounts,
            "aadhaar_numbers": self.aadhaar_numbers,
            "pan_numbers": self.pan_numbers,
            "scam_indicators": self.scam_indicators,
            "scam_type": self.scam_type,
            "risk_level": self.risk_level,
        }


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            result.append(cleaned)
    return result


def _classify_scam_type(text_lower: str) -> str:
    scores: dict[str, int] = {}
    for scam_type, keywords in _SCAM_TYPES.items():
        hits = sum(1 for kw in keywords if kw in text_lower)
        if hits:
            scores[scam_type] = hits
    if not scores:
        return "unknown"
    return max(scores, key=lambda k: scores[k])


def _assess_risk(intel: RegexIntelligence, scam_probability: float) -> str:
    score = 0
    if scam_probability >= 0.9:
        score += 4
    elif scam_probability >= 0.7:
        score += 3
    elif scam_probability >= 0.5:
        score += 2

    score += len(intel.urls) * 2
    score += len(intel.phone_numbers)
    score += len(intel.payment_details) * 2
    score += len(intel.crypto_wallets) * 2
    score += len(intel.upi_ids) * 2
    score += len(intel.aadhaar_numbers) * 3
    score += len(intel.pan_numbers) * 2
    score += min(len(intel.scam_indicators), 5)

    if score >= 12:
        return "critical"
    if score >= 7:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def extract_regex_intelligence(
    text: str, scam_probability: float = 0.0
) -> RegexIntelligence:
    """Run all regex patterns against text and return structured intel."""

    text_lower = text.lower()

    phones = _dedupe(_PHONE.findall(text))
    emails = _dedupe(_EMAIL.findall(text))
    urls = _dedupe(_URL.findall(text))

    # UPI IDs look like emails; filter out real emails
    upi_candidates = _dedupe(_UPI.findall(text))
    upi_ids = [u for u in upi_candidates if u not in emails]

    # Amounts
    amounts = _dedupe(
        _AMOUNT_INR.findall(text)
        + _AMOUNT_USD.findall(text)
        + _AMOUNT_GENERIC.findall(text)
    )

    # Payment / card
    payment_details = _dedupe(
        _CARD_PARTIAL.findall(text) + upi_ids
    )

    crypto_wallets = _dedupe(_CRYPTO_WALLET.findall(text))
    aadhaar = _dedupe(_AADHAAR.findall(text))
    pan = _dedupe(_PAN.findall(text))

    # Signal detection
    indicators: list[str] = []
    for category, keywords in _SCAM_SIGNALS.items():
        for kw in keywords:
            if kw in text_lower:
                indicators.append(f"{category}: {kw}")

    scam_type = _classify_scam_type(text_lower)

    intel = RegexIntelligence(
        phone_numbers=phones,
        email_addresses=emails,
        urls=urls,
        upi_ids=upi_ids,
        payment_details=payment_details,
        crypto_wallets=crypto_wallets,
        amounts=amounts,
        aadhaar_numbers=aadhaar,
        pan_numbers=pan,
        scam_indicators=_dedupe(indicators),
        scam_type=scam_type,
    )
    intel.risk_level = _assess_risk(intel, scam_probability)
    return intel
