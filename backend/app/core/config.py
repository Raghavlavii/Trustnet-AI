"""Application configuration loaded from environment variables."""

from dataclasses import dataclass, field
import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_PATH = PROJECT_ROOT / ".env"
load_dotenv(ENV_PATH)


def _parse_cors_origins(value: str) -> tuple[str, ...]:
    origins = [origin.strip() for origin in value.split(",") if origin.strip()]
    return tuple(origins or ["*"])


@dataclass(frozen=True)
class Settings:
    """Runtime settings for API, ML model, LLM provider, and database."""

    app_name: str = "TrustNet AI"
    project_root: Path = PROJECT_ROOT

    # Groq LLM
    groq_api_key: str = os.getenv("GROQ_API_KEY", "")
    groq_model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

    # ML model
    model_path: Path = Path(
        os.getenv("MODEL_PATH", str(PROJECT_ROOT / "ml" / "models" / "model.pkl"))
    )

    # CORS
    cors_origins: tuple[str, ...] = _parse_cors_origins(
        os.getenv("CORS_ORIGINS", "*")
    )

    # Database — defaults to local SQLite, override with DATABASE_URL for Postgres
    database_url: str = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{(PROJECT_ROOT / 'trustnet_intel.db').resolve()}",
    )
    print("🔥 USING DB:", (PROJECT_ROOT / "trustnet_intel.db").resolve())

    # Intelligence extraction
    # Scam probability threshold above which deep extraction is triggered
    extraction_threshold: float = float(os.getenv("EXTRACTION_THRESHOLD", "0.5"))

    # Report output directory
    reports_dir: Path = Path(
        os.getenv("REPORTS_DIR", str(PROJECT_ROOT / "reports"))
    )

    # Environment
    environment: str = os.getenv("ENVIRONMENT", "development")

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


settings = Settings()
