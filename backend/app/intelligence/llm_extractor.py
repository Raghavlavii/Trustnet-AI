"""LLM-powered structured intelligence extraction via Groq."""

from __future__ import annotations

import json
import logging
from typing import Any

from groq import Groq

from app.core.config import settings

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a cybercrime intelligence analyst. Your task is to extract structured information from a suspected scam message to help law enforcement.

Extract and return ONLY a JSON object with these fields (use empty lists/null if not found):
{
  "sender_names": [],           // Names or aliases used by the scammer
  "organizations": [],          // Organizations impersonated (banks, companies, govt bodies)
  "phone_numbers": [],          // Any phone numbers mentioned
  "email_addresses": [],        // Any email addresses
  "urls": [],                   // Any links or domains
  "payment_methods": [],        // Payment methods requested (UPI, wire, crypto, etc.)
  "amounts_requested": [],      // Any amounts of money mentioned
  "threats_made": [],           // Any threats used to pressure the victim
  "false_claims": [],           // False claims made (e.g. "you won a prize")
  "urgency_tactics": [],        // Urgency tactics used
  "scam_summary": "",           // One sentence summary of the scam
  "target_demographic": "",     // Who this scam targets (elderly, job seekers, etc.)
  "recommended_authority": ""   // Which authority to report to (cybercrime cell, RBI, etc.)
}

Return ONLY valid JSON. No markdown, no explanation."""


def extract_llm_intelligence(text: str) -> dict[str, Any]:
    """Use Groq LLM to extract structured intelligence from a scam message."""

    if not settings.groq_api_key or settings.groq_api_key in ("", "your_key_here"):
        logger.warning("GROQ_API_KEY not set; skipping LLM extraction.")
        return {"error": "LLM unavailable — GROQ_API_KEY not configured."}

    try:
        client = Groq(api_key=settings.groq_api_key)
        response = client.chat.completions.create(
            model=settings.groq_model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": f"Extract intelligence from this message:\n\n{text[:4000]}",
                },
            ],
            temperature=0,
            max_tokens=800,
            response_format={"type": "json_object"},
        )

        content = response.choices[0].message.content or ""
        return json.loads(content)

    except json.JSONDecodeError as exc:
        logger.error("LLM returned invalid JSON: %s", exc)
        return {"error": f"JSON parse error: {exc}"}
    except Exception as exc:
        logger.error("LLM extraction failed: %s", exc)
        return {"error": f"{exc.__class__.__name__}: {exc}"}
