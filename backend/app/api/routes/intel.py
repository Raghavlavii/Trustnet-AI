"""Routes for retrieving intelligence records and reports."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Conversation, ExtractedIntel, Report
from app.db.session import get_db

router = APIRouter(tags=["intelligence"])


# ---------------------------------------------------------------------------
# Conversations
# ---------------------------------------------------------------------------

@router.get("/conversations")
async def list_conversations(
    limit: int = 50,
    offset: int = 0,
    label: str | None = None,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """List stored conversations, optionally filtered by label (Scam/Safe)."""
    query = db.query(Conversation).order_by(Conversation.created_at.desc())
    if label:
        query = query.filter(Conversation.label == label)
    total = query.count()
    rows = query.offset(offset).limit(limit).all()

    return JSONResponse({
        "total": total,
        "offset": offset,
        "limit": limit,
        "conversations": [
            {
                "id": c.id,
                "session_id": c.session_id,
                "label": c.label,
                "trust_score": c.trust_score,
                "ml_scam_probability": c.ml_scam_probability,
                "status": c.status,
                "created_at": c.created_at.isoformat(),
                "has_intel": bool(c.extracted_intel),
                "has_report": bool(c.reports),
            }
            for c in rows
        ],
    })


@router.get("/conversations/{session_id}")
async def get_conversation(
    session_id: str,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Retrieve full detail for a single conversation."""
    conv = db.query(Conversation).filter_by(session_id=session_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")

    intel = (
        db.query(ExtractedIntel)
        .filter_by(conversation_id=conv.id)
        .order_by(ExtractedIntel.created_at.desc())
        .first()
    )

    return JSONResponse({
        "conversation": {
            "id": conv.id,
            "session_id": conv.session_id,
            "label": conv.label,
            "trust_score": conv.trust_score,
            "ml_scam_probability": conv.ml_scam_probability,
            "llm_analysis": conv.llm_analysis,
            "status": conv.status,
            "created_at": conv.created_at.isoformat(),
        },
        "messages": [
            {"role": m.role, "content": m.content, "timestamp": m.created_at.isoformat()}
            for m in sorted(conv.messages, key=lambda m: m.created_at)
        ],
        "extracted_intel": _intel_to_dict(intel),
        "reports": [
            {"report_id": r.report_id, "created_at": r.created_at.isoformat()}
            for r in conv.reports
        ],
    })


# ---------------------------------------------------------------------------
# Intelligence
# ---------------------------------------------------------------------------

@router.get("/intel/{session_id}")
async def get_intel(
    session_id: str,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return extracted intelligence for a conversation session."""
    conv = db.query(Conversation).filter_by(session_id=session_id).first()
    if not conv:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found.")

    intel = (
        db.query(ExtractedIntel)
        .filter_by(conversation_id=conv.id)
        .order_by(ExtractedIntel.created_at.desc())
        .first()
    )
    if not intel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No intelligence extracted for this session (may not have crossed scam threshold).",
        )

    return JSONResponse(_intel_to_dict(intel))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@router.get("/reports")
async def list_reports(
    limit: int = 20,
    offset: int = 0,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """List all generated reports."""
    total = db.query(Report).count()
    rows = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return JSONResponse({
        "total": total,
        "reports": [
            {
                "report_id": r.report_id,
                "session_id": r.conversation.session_id if r.conversation else None,
                "created_at": r.created_at.isoformat(),
                "risk_level": (r.content or {})
                    .get("incident_summary", {})
                    .get("risk_level", "unknown"),
            }
            for r in rows
        ],
    })


@router.get("/reports/{report_id}")
async def get_report(
    report_id: str,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Return the full structured report JSON."""
    report = db.query(Report).filter_by(report_id=report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")
    return JSONResponse(report.content)


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: str,
    db: Session = Depends(get_db),
) -> FileResponse:
    """Download the report as a JSON file."""
    report = db.query(Report).filter_by(report_id=report_id).first()
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found.")

    file_path = settings.reports_dir / f"{report_id}.json"
    if not file_path.exists():
        # Re-write if missing
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(json.dumps(report.content, indent=2), encoding="utf-8")

    return FileResponse(
        path=str(file_path),
        media_type="application/json",
        filename=f"{report_id}.json",
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _intel_to_dict(intel: ExtractedIntel | None) -> dict:
    if not intel:
        return {}
    return {
        "id": intel.id,
        "phone_numbers": intel.phone_numbers or [],
        "email_addresses": intel.email_addresses or [],
        "urls": intel.urls or [],
        "payment_details": intel.payment_details or [],
        "names_aliases": intel.names_aliases or [],
        "organizations": intel.organizations or [],
        "amounts": intel.amounts or [],
        "scam_type": intel.scam_type,
        "scam_indicators": intel.scam_indicators or [],
        "risk_level": intel.risk_level,
        "llm_extracted": intel.llm_extracted or {},
        "created_at": intel.created_at.isoformat(),
    }
