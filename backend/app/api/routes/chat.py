"""Chat follow-up route — AI investigation loop with decision engine."""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Conversation, Message, ExtractedIntel
from app.services.followup_agent import generate_followup

router = APIRouter(tags=["chat"])


# ✅ Request model (FIXES YOUR MAIN BUG)
class ChatRequest(BaseModel):
    user_message: str


@router.post("/chat-followup/{session_id}")
async def chat_followup(
    session_id: str,
    payload: ChatRequest,
    db: Session = Depends(get_db)
):
    user_message = payload.user_message

    # 1. Get conversation
    conv = db.query(Conversation).filter_by(session_id=session_id).first()
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    # 2. Save user message
    db.add(Message(
        conversation_id=conv.id,
        role="user",
        content=user_message
    ))

    # 3. Get conversation messages
    messages = [
        {"role": m.role, "content": m.content}
        for m in conv.messages
    ]

    # 4. Get extracted intelligence
    intel_row = (
        db.query(ExtractedIntel)
        .filter_by(conversation_id=conv.id)
        .order_by(ExtractedIntel.created_at.desc())
        .first()
    )

    intel = {}
    if intel_row:
        intel = {
            "scam_type": intel_row.scam_type,
            "risk_level": intel_row.risk_level,
            "indicators": intel_row.scam_indicators or []
        }

    # 5. Generate AI reply + decision
    ai_reply, status = generate_followup(messages, intel)

    # 6. Save AI message
    db.add(Message(
        conversation_id=conv.id,
        role="assistant",
        content=ai_reply
    ))

    db.commit()

    return {
        "reply": ai_reply,
        "status": status,
        "session_id": session_id
    }