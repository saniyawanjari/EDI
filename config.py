"""All settings in one place (Phase 5). Values come from environment variables or the .env file.

Priority: real environment variable > .env file > default below.
Nothing secret is hard-coded here: ADMIN_KEY has NO default on purpose
(if it is empty, every admin endpoint refuses to work = fail closed).
"""
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # Audit database. SQLite by default; PostgreSQL example is in .env.example.
    database_url: str = "sqlite:///./audit.db"

    # Where Open Policy Agent answers (the "allow" rule of package authz).
    opa_url: str = "http://localhost:8181/v1/data/authz/allow"

    # Secret for admin endpoints (x-admin-key header). Empty = admin disabled.
    admin_key: str = ""

    # "full" = real system. "header_only" and "none" are WEAK BASELINES used only
    # by the evaluation (Phase 7) to show what happens without our protections.
    security_mode: Literal["full", "header_only", "none"] = "full"

    # Optional override for the capability-token signing key file.
    server_key_path: str = ""

    # Browser origin allowed to call the API (the React dashboard).
    cors_origin: str = "http://localhost:5173"

    # Address the demo router uses to call this same API (dev only).
    self_url: str = "http://127.0.0.1:8000"


settings = Settings()
