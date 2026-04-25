"""Generate structured cybercrime intelligence reports from conversation records."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Conversation, ExtractedIntel, Report


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_conversation_data(
    db: Session, conversation: Conversation
) -> dict[str, Any]:
    """Build a complete dict from a Conversation and its related records."""

    intel: ExtractedIntel | None = (
        db.query(ExtractedIntel)
        .filter_by(conversation_id=conversation.id)
        .order_by(ExtractedIntel.created_at.desc())
        .first()
    )

    messages = [
        {
            "role": m.role,
            "content": m.content,
            "timestamp": m.created_at.isoformat(),
        }
        for m in sorted(conversation.messages, key=lambda m: m.created_at)
    ]

    llm_data: dict[str, Any] = {}
    if intel and intel.llm_extracted:
        llm_data = intel.llm_extracted  # type: ignore[assignment]

    return {
        "conversation": {
            "session_id": conversation.session_id,
            "label": conversation.label,
            "trust_score": conversation.trust_score,
            "ml_scam_probability": conversation.ml_scam_probability,
            "llm_analysis": conversation.llm_analysis,
            "created_at": conversation.created_at.isoformat(),
            "status": conversation.status,
        },
        "messages": messages,
        "extracted_intel": {
            "phone_numbers": getattr(intel, "phone_numbers", []) or [],
            "email_addresses": getattr(intel, "email_addresses", []) or [],
            "urls": getattr(intel, "urls", []) or [],
            "payment_details": getattr(intel, "payment_details", []) or [],
            "names_aliases": getattr(intel, "names_aliases", []) or [],
            "organizations": getattr(intel, "organizations", []) or [],
            "amounts": getattr(intel, "amounts", []) or [],
            "scam_type": getattr(intel, "scam_type", "unknown"),
            "scam_indicators": getattr(intel, "scam_indicators", []) or [],
            "risk_level": getattr(intel, "risk_level", "unknown"),
        },
        "llm_analysis": llm_data,
    }


def build_report(data: dict[str, Any], report_id: str) -> dict[str, Any]:
    """Construct a structured report dict suitable for JSON export."""

    conv = data["conversation"]
    intel = data["extracted_intel"]
    llm = data.get("llm_analysis", {})

    # Authority recommendations based on scam type
    authority_map = {
        "phishing": "Cybercrime Cell (cybercrime.gov.in) / CERT-In",
        "banking_fraud": "RBI Ombudsman + Cybercrime Cell",
        "lottery_fraud": "Local Police + National Consumer Helpline (1800-11-4000)",
        "job_scam": "Ministry of Labour + Cybercrime Portal",
        "investment_scam": "SEBI + Cybercrime Cell",
        "delivery_scam": "Cybercrime Cell + Courier Company Fraud Wing",
        "refund_scam": "Consumer Forum + Cybercrime Cell",
        "tech_support": "Cybercrime Cell + ISP Abuse Team",
        "romance_scam": "Cybercrime Cell (report confidentially)",
    }

    scam_type = intel.get("scam_type", "unknown")
    recommended_authority = (
        llm.get("recommended_authority")
        or authority_map.get(scam_type, "Cybercrime Cell (cybercrime.gov.in)")
    )

    return {
        "report_metadata": {
            "report_id": report_id,
            "generated_at": _utcnow_iso(),
            "report_version": "1.0",
            "classification": "CYBERCRIME INTELLIGENCE REPORT",
            "for_authority_use": True,
        },
        "incident_summary": {
            "session_id": conv["session_id"],
            "detected_at": conv["created_at"],
            "verdict": conv["label"],
            "trust_score": conv["trust_score"],
            "ml_scam_probability": conv["ml_scam_probability"],
            "scam_type": scam_type,
            "risk_level": intel.get("risk_level", "unknown"),
            "scam_summary": llm.get("scam_summary") or conv.get("llm_analysis", ""),
        },
        "extracted_intelligence": {
            "contact_information": {
                "phone_numbers": intel.get("phone_numbers", []),
                "email_addresses": intel.get("email_addresses", []),
                "urls": intel.get("urls", []),
            },
            "financial_information": {
                "payment_methods": intel.get("payment_details", []),
                "amounts_mentioned": intel.get("amounts", []),
            },
            "identity_information": {
                "names_or_aliases": intel.get("names_aliases", []),
                "organizations_impersonated": intel.get("organizations", []),
            },
            "scam_tactics": {
                "indicators": intel.get("scam_indicators", []),
                "urgency_tactics": llm.get("urgency_tactics", []),
                "threats_made": llm.get("threats_made", []),
                "false_claims": llm.get("false_claims", []),
            },
        },
        "conversation_timeline": data.get("messages", []),
        "recommendations": {
            "report_to": recommended_authority,
            "target_demographic": llm.get("target_demographic", "General public"),
            "immediate_actions": _get_immediate_actions(scam_type, intel),
        },
        "technical_metadata": {
            "detection_method": "ML (SGDClassifier) + LLM Analysis (Groq)",
            "ml_model": "TrustNet AI v1.0",
            "extraction_methods": ["regex", "llm_structured"],
        },
    }


def _get_immediate_actions(scam_type: str, intel: dict[str, Any]) -> list[str]:
    actions = ["Document all evidence before contacting authorities"]

    if intel.get("urls"):
        actions.append("Report malicious URLs to CERT-In (incident@cert-in.org.in)")
    if intel.get("phone_numbers"):
        actions.append("Report phone numbers to DND (1909) and Sanchar Saathi portal")
    if intel.get("payment_details"):
        actions.append("Contact bank/UPI provider immediately if any payment was made")

    type_actions = {
        "banking_fraud": "Call RBI helpline 14440 immediately",
        "phishing": "Change passwords for all affected accounts immediately",
        "investment_scam": "File complaint on SEBI SCORES portal (scores.gov.in)",
        "job_scam": "Report to National Career Service Portal",
    }
    if scam_type in type_actions:
        actions.append(type_actions[scam_type])

    actions.append("File online FIR at cybercrime.gov.in or call 1930")
    return actions


def generate_and_store_report(
    db: Session,
    conversation: Conversation,
) -> Report:
    """Generate a report, persist it to the database, and return the Report row."""

    data = _load_conversation_data(db, conversation)
    report_id = f"TNR-{uuid.uuid4().hex[:12].upper()}"
    report_content = build_report(data, report_id)

    report = Report(
        conversation_id=conversation.id,
        report_id=report_id,
        format="json",
        content=report_content,
    )
    db.add(report)
    db.flush()
    db.refresh(report)

    # Also write to filesystem for easy sharing
    _write_report_file(report_id, report_content)

    return report


def _write_report_file(report_id: str, content: dict[str, Any]) -> None:
    """Save report JSON to the reports directory."""
    reports_dir = settings.reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)
    out_path = reports_dir / f"{report_id}.json"
    out_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
