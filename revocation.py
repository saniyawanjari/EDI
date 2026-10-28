"""Revocation list (Phase 5: moved into the revoked_tokens table).

A 'jti' is the unique id of a token or a credential. Revoking it makes both
the token check and the credential check fail from now on.
"""
from datetime import datetime, timezone

from identity import registry
from db import SessionLocal
from models import RevokedToken


def revoke(jti: str) -> None:
    with SessionLocal() as session:
        if session.get(RevokedToken, jti) is None:
            session.add(RevokedToken(jti=jti, revoked_at=datetime.now(timezone.utc).isoformat()))
            session.commit()
    # Also mark it in the identity registry so a revoked CREDENTIAL cannot get new tokens.
    registry.revoke_credential(jti)


def is_revoked(jti: str) -> bool:
    with SessionLocal() as session:
        return session.get(RevokedToken, jti) is not None
