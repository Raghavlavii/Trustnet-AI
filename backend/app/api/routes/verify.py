"""Verification API route — ML detection + intelligence extraction + DB storage + follow-up trigger."""

from __future__ import annotations

import uuid
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import Conversation, ExtractedIntel, Message
from app.db.session import get_db
from app.intelligence.pipeline import run_extraction_pipeline
from app.reports.generator import generate_and_store_report
from app.services.groq_service import analyze_with_groq
from app.services.scam_detector import scam_detector

logger = logging.getLogger(__name__)
router = APIRouter(tags=["verification"])


# ---------------------------
# Request / Response Models
# ---------------------------

class VerifyRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)


class VerifyResponse(BaseModel):
    label: str
    trust_score: float
    ml_scam_probability: float
    llm_analysis: str
    session_id: str
    intel_extracted: bool
    report_id: str | None = None
    followup_available: bool  # ✅ NEW


# ---------------------------
# Main Endpoint
# ---------------------------

@router.post("/verify", response_model=VerifyResponse)
async def verify_content(
    payload: VerifyRequest,
    db: Session = Depends(get_db),
) -> VerifyResponse:
    """Run ML scam detection, extract intelligence, persist to DB, generate report."""

    text = payload.text.strip()
    if not text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Text must not be empty.",
        )

    # --- ML prediction ---
    try:
        ml_result = scam_detector.predict(text)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"ML prediction failed: {exc.__class__.__name__}",
        ) from exc

    # --- LLM explanation ---
    llm_analysis = analyze_with_groq(text)

    label = str(ml_result["label"])
    trust_score = float(ml_result["trust_score"])
    ml_prob = float(ml_result["ml_scam_probability"])

    # --- Create conversation ---
    session_id = uuid.uuid4().hex

    conversation = Conversation(
        session_id=session_id,
        label=label,
        trust_score=trust_score,
        ml_scam_probability=ml_prob,
        llm_analysis=llm_analysis,
        status="flagged" if label == "Scam" else "analyzed",
    )

    db.add(conversation)
    db.flush()  # get ID

    # --- Save user message ---
    db.add(Message(
        conversation_id=conversation.id,
        role="user",
        content=text,
    ))

    intel_extracted = False
    report_id: str | None = None

    # --- Intelligence extraction ---
    if ml_prob >= settings.extraction_threshold:
        try:
            intel_data = run_extraction_pipeline(
                text=text,
                scam_probability=ml_prob,
                use_llm=bool(settings.groq_api_key),
            )

            intel_row = ExtractedIntel(
                conversation_id=conversation.id,
                phone_numbers=intel_data.get("phone_numbers", []),
                email_addresses=intel_data.get("email_addresses", []),
                urls=intel_data.get("urls", []),
                payment_details=intel_data.get("payment_details", []),
                names_aliases=intel_data.get("names_aliases", []),
                organizations=intel_data.get("organizations", []),
                amounts=intel_data.get("amounts", []),
                llm_extracted=intel_data.get("llm_extracted", {}),
                scam_type=intel_data.get("scam_type", "unknown"),
                scam_indicators=intel_data.get("scam_indicators", []),
                risk_level=intel_data.get("risk_level", "low"),
            )

            db.add(intel_row)
            db.flush()

            intel_extracted = True

            # --- Generate report ---
            report = generate_and_store_report(db=db, conversation=conversation)
            report_id = report.report_id

        except Exception as exc:
            logger.error("Intelligence extraction failed: %s", exc, exc_info=True)

    # --- Commit everything ---
    db.commit()

    # --- Return response ---
    return VerifyResponse(
        label=label,
        trust_score=trust_score,
        ml_scam_probability=ml_prob,
        llm_analysis=llm_analysis,
        session_id=session_id,
        intel_extracted=intel_extracted,
        report_id=report_id,
        followup_available=(label == "Scam"),  # ✅ KEY FEATURE
    )