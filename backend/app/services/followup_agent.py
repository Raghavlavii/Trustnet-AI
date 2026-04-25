"""Follow-up AI agent — conversation + decision engine."""

from app.core.config import settings
from groq import Groq


def generate_followup(messages: list[dict], intel: dict):
    """
    Returns:
        (reply: str, status: str)

    status:
        - continue
        - confirmed_scam
        - likely_safe
    """

    # -------------------------
    # 🔥 DECISION ENGINE
    # -------------------------

    risk = (intel.get("risk_level") or "").lower()
    indicators = intel.get("indicators", [])

    # Strong scam detection
    if risk == "high" or any("otp" in str(i).lower() for i in indicators):
        return (
            "🚨 This interaction confirms scam behavior (OTP / sensitive data request). Ending investigation.",
            "confirmed_scam"
        )

    # Likely safe
    if risk == "low" and len(messages) > 3:
        return (
            "✅ No strong scam signals detected. Conversation appears safe. Ending investigation.",
            "likely_safe"
        )

    # -------------------------
    # 🤖 LLM RESPONSE
    # -------------------------

    if not settings.groq_api_key:
        return ("Can you explain more details about this offer?", "continue")

    client = Groq(api_key=settings.groq_api_key)

    prompt = f"""
You are pretending to be a normal person talking to a scammer.

Goals:
- Act natural (not robotic)
- Ask smart questions
- Extract details (money, links, phone, process)
- Keep it short

Known intelligence:
{intel}

Conversation so far:
{messages}

Generate the next message ONLY.
Do not explain anything.
"""

    try:
        response = client.chat.completions.create(
            model=settings.groq_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
            max_tokens=120,
        )

        reply = response.choices[0].message.content.strip()

    except Exception as e:
        reply = "Can you explain how this process works?"

    return (reply, "continue")