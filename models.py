"""Database tables (Phase 5)."""
from sqlalchemy import Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from db import Base


class Agent(Base):
    __tablename__ = "agents"
    did: Mapped[str] = mapped_column(String(200), primary_key=True)
    role: Mapped[str] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(String(20), default="active")
    created_at: Mapped[str] = mapped_column(String(40))


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    # Timestamp is stored as ISO text (UTC) so the hash is identical after a database round trip.
    timestamp: Mapped[str] = mapped_column(String(40), index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_did: Mapped[str | None] = mapped_column(String(200), index=True, nullable=True)
    role: Mapped[str | None] = mapped_column(String(50), nullable=True)
    action: Mapped[str] = mapped_column(String(50))
    resource: Mapped[str | None] = mapped_column(String(300), nullable=True)
    decision: Mapped[str] = mapped_column(String(8), index=True)  # ALLOW / DENY / ERROR
    reason: Mapped[str] = mapped_column(String(500))
    http_status: Mapped[int] = mapped_column(Integer)
    latency_ms: Mapped[float] = mapped_column(Float)
    token_verify_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    opa_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    token_jti: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str] = mapped_column(String(64))
    row_hash: Mapped[str] = mapped_column(String(64))


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    jti: Mapped[str] = mapped_column(String(64), primary_key=True)
    revoked_at: Mapped[str] = mapped_column(String(40))
