"""Groq LLM integration for short explainable scam analysis."""

from functools import lru_cache

from app.core.config import settings

PROMPT = (
    "Classify the message as Scam or Safe and give a short 1-line reason. "
    "Format: Label - Reason"
)


@lru_cache(maxsize=1)
def _get_client():
    from groq import Groq
    return Groq(api_key=settings.groq_api_key)


def analyze_with_groq(text: str) -> str:
    """Return a concise LLM explanation, or a safe fallback on API failure."""

    if not settings.groq_api_key or settings.groq_api_key in ("", "your_key_here"):
        return "LLM unavailable - Set GROQ_API_KEY in .env for explanation."

    try:
        response = _get_client().chat.completions.create(
            model=settings.groq_model,
            messages=[
                {"role": "system", "content": "You are a concise digital safety analyst."},
                {"role": "user", "content": f"{PROMPT}\n\nMessage:\n{text[:4000]}"},
            ],
            temperature=0,
            max_tokens=80,
        )
        content = response.choices[0].message.content
        return content.strip() if content else "LLM unavailable - Empty response."
    except Exception as exc:
        return (
            "LLM unavailable - "
            f"{exc.__class__.__name__}: explanation could not be generated."
        )
