"""FastAPI entry point for TrustNet AI."""

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes.intel import router as intel_router
from app.api.routes.verify import router as verify_router
from app.api.routes.chat import router as chat_router

from app.core.config import settings
from app.db.session import init_db
from app.services.scam_detector import scam_detector


# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.INFO if settings.is_production else logging.DEBUG,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------- App ----------------
app = FastAPI(
    title=settings.app_name,
    version="2.1.0",
    description=(
        "AI-powered digital content verification, intelligence extraction, "
        "interactive investigation, and cybercrime reporting API."
    ),
)


# ---------------- CORS ----------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------- Routers (MUST COME FIRST) ----------------
app.include_router(verify_router)
app.include_router(intel_router)
app.include_router(chat_router)


# ---------------- Static Frontend (SAFE PATH FIX) ----------------
# This ensures correct path even if folder structure shifts
FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"

if not FRONTEND_DIR.exists():
    raise RuntimeError(f"Frontend directory not found: {FRONTEND_DIR}")


app.mount(
    "/",
    StaticFiles(directory=FRONTEND_DIR, html=True),
    name="frontend",
)


# ---------------- Startup ----------------
@app.on_event("startup")
async def startup_event() -> None:
    """Initialise the database on first start."""
    init_db()
    logger.info("Database initialised.")
    logger.info("Model loaded: %s", scam_detector.model_loaded)
    logger.info("DB URL: %s", settings.database_url)

    settings.reports_dir.mkdir(parents=True, exist_ok=True)


# ---------------- Health ----------------
@app.get("/health", tags=["system"])
async def health_check() -> dict:
    """Operational health endpoint."""
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": "2.1.0",
        "model_loaded": scam_detector.model_loaded,
        "model_metadata": scam_detector.metadata,
        "environment": settings.environment,
    }