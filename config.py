"""Application configuration."""
import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent


class Settings:
    APP_NAME: str = "Sentinel"
    APP_VERSION: str = "2.0.0"
    DEBUG: bool = os.getenv("DEBUG", "true").lower() == "true"
    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production-use-openssl-rand-hex-32")

    HOST: str = os.getenv("HOST", "127.0.0.1")
    PORT: int = int(os.getenv("PORT", "5050"))

    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite+aiosqlite:///{BASE_DIR / 'sentinel.db'}")
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    JWT_SECRET: str = os.getenv("JWT_SECRET", SECRET_KEY)
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = int(os.getenv("JWT_EXPIRY_HOURS", "24"))

    SCREENSHOTS_DIR: Path = BASE_DIR / "reports" / "screenshots"
    REPORTS_DIR: Path = BASE_DIR / "reports" / "exports"

    MAX_PAGES_DEFAULT: int = 50
    MAX_DEPTH_DEFAULT: int = 4
    SCAN_TIMEOUT_SECONDS: int = 300

    ENABLE_SCHEDULER: bool = os.getenv("ENABLE_SCHEDULER", "true").lower() == "true"


settings = Settings()
