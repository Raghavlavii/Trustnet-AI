"""Orchestrates regex + LLM extraction into a unified intelligence record."""

from __future__ import annotations

import logging
from typing import Any

from app.intelligence.llm_extractor import extract_llm_intelligence
from app.intelligence.regex_extractor import RegexIntelligence, extract_regex_intelligence

logger = logging.getLogger(__name__)


def run_extraction_pipeline(
    text: str,
    scam_probability: float,
    use_llm: bool = True,
) -> dict[str, Any]:
    """
    Run full intelligence extraction on a message.

    Returns a dict ready to be stored in ExtractedIntel.
    """

    # --- Stage 1: Regex extraction (always runs, fast, deterministic) ---
    regex_intel: RegexIntelligence = extract_regex_intelligence(text, scam_probability)

    # --- Stage 2: LLM extraction (runs when scam threshold met) ---
    llm_intel: dict[str, Any] = {}
    if use_llm:
        llm_intel = extract_llm_intelligence(text)
        if "error" in llm_intel:
            logger.warning("LLM extraction partial failure: %s", llm_intel["error"])

    # --- Merge: regex is authoritative for raw values; LLM adds semantic context ---
    merged_phones = _merge_lists(
        regex_intel.phone_numbers,
        llm_intel.get("phone_numbers", []),
    )
    merged_emails = _merge_lists(
        regex_intel.email_addresses,
        llm_intel.get("email_addresses", []),
    )
    merged_urls = _merge_lists(
        regex_intel.urls,
        llm_intel.get("urls", []),
    )
    merged_payment = _merge_lists(
        regex_intel.payment_details,
        llm_intel.get("payment_methods", []),
    )
    merged_amounts = _merge_lists(
        regex_intel.amounts,
        llm_intel.get("amounts_requested", []),
    )
    merged_names = llm_intel.get("sender_names", [])
    merged_orgs = llm_intel.get("organizations", [])

    return {
        # Regex fields
        "phone_numbers": merged_phones,
        "email_addresses": merged_emails,
        "urls": merged_urls,
        "payment_details": merged_payment,
        "names_aliases": merged_names,
        "organizations": merged_orgs,
        "amounts": merged_amounts,
        # Scam classification
        "scam_type": regex_intel.scam_type,
        "scam_indicators": regex_intel.scam_indicators,
        "risk_level": regex_intel.risk_level,
        # Full LLM analysis stored as-is for report generation
        "llm_extracted": llm_intel,
    }


def _merge_lists(*lists: list[str]) -> list[str]:
    """Combine multiple lists, deduplicate preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for lst in lists:
        for item in lst:
            cleaned = str(item).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                result.append(cleaned)
    return result
