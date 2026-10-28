"""Short-lived capability tokens (Phase 4).

A token says: "agent <sub> may do <action> on <resource>" for 5 minutes.
It is signed (EdDSA) with the Supervisor's own key in server_key.pem.
Having the right ROLE is not enough: the token must also contain the capability.
"""
import os
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt  # PyJWT

from config import settings
from identity.did import generate_private_key, load_private_key_from_pem, private_key_to_pem

PROJECT_ROOT = Path(__file__).resolve().parent
SERVER_KEY_PATH = Path(os.getenv("SERVER_KEY_PATH") or settings.server_key_path or PROJECT_ROOT / "server_key.pem")

AUDIENCE = "soc-supervisor"
ISSUER = "soc-supervisor"
TOKEN_TTL_SECONDS = 300  # 5 minutes

# Which resource each action works on. Only "ip:*" and "host:*" are wildcards.
# (report_threat -> "threat_report" is our addition: the spec did not list it.)
ACTION_RESOURCE = {
    "read_logs": "server_logs.txt",
    "report_threat": "threat_report",
    "block_ip": "ip:*",
    "isolate_host": "host:*",
}


class TokenError(Exception):
    """Token is not acceptable (401). The message is the reason."""


class ScopeError(Exception):
    """The agent asked for more than its credential allows (403)."""


_key_lock = threading.Lock()
_cached_key = None


def get_server_key():
    """Load server_key.pem, or create it the first time (the file is git-ignored)."""
    global _cached_key
    with _key_lock:
        if _cached_key is None:
            if SERVER_KEY_PATH.exists():
                _cached_key = load_private_key_from_pem(SERVER_KEY_PATH.read_bytes())
            else:
                _cached_key = generate_private_key()
                SERVER_KEY_PATH.write_bytes(private_key_to_pem(_cached_key))
                try:
                    os.chmod(SERVER_KEY_PATH, 0o600)
                except OSError:
                    pass
        return _cached_key


def resource_matches(pattern: str, resource: str) -> bool:
    """Does a capability resource (maybe a wildcard) cover this concrete resource?"""
    if pattern in ("ip:*", "host:*"):
        prefix = pattern[:-1]  # "ip:" or "host:"
        return resource.startswith(prefix) and len(resource) > len(prefix)
    return pattern == resource  # everything else must match exactly


def has_capability(capabilities: list, action: str, resource: str) -> bool:
    return any(
        isinstance(c, dict) and c.get("action") == action
        and isinstance(c.get("resource"), str) and resource_matches(c["resource"], resource)
        for c in capabilities
    )


def capabilities_from_actions(allowed_actions: list[str]) -> list[dict]:
    """Turn the credential's allowed_actions into capabilities. Unknown actions are dropped."""
    return [{"action": a, "resource": ACTION_RESOURCE[a]} for a in allowed_actions if a in ACTION_RESOURCE]


def issue_token(identity: dict, requested: list[dict] | None = None,
                ttl_seconds: int = TOKEN_TTL_SECONDS) -> str:
    """identity = result of authenticate_agent(). 'requested' may NARROW the capabilities
    (e.g. only 'block_ip on ip:10.0.0.5'); it can never add new ones.
    ttl_seconds can be negative: that is only used by tests/evaluation to make an expired token."""
    full = capabilities_from_actions(identity["allowed_actions"])
    if requested is None:
        capabilities = full
    else:
        if len(requested) > 20:
            raise ScopeError("too many capabilities requested")
        for cap in requested:
            if not any(f["action"] == cap["action"] and resource_matches(f["resource"], cap["resource"])
                       for f in full):
                raise ScopeError(f"credential does not allow {cap['action']} on {cap['resource']}")
        capabilities = [{"action": c["action"], "resource": c["resource"]} for c in requested]

    now = datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": identity["did"],
        "role": identity["role"],
        "capabilities": capabilities,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
    }
    return jwt.encode(claims, get_server_key(), algorithm="EdDSA")


def verify_token(token: str) -> dict:
    """Check signature, expiry, audience and revocation. Returns claims or raises TokenError."""
    try:
        claims = jwt.decode(
            token,
            get_server_key().public_key(),
            algorithms=["EdDSA"],  # only EdDSA ("alg: none" is rejected)
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "sub", "jti", "aud", "iss"]},
        )
    except jwt.ExpiredSignatureError:
        raise TokenError("token expired")
    except jwt.InvalidAudienceError:
        raise TokenError("token has the wrong audience")
    except jwt.InvalidTokenError:
        raise TokenError("token is invalid (forged, damaged or wrongly signed)")

    caps = claims.get("capabilities")
    if not isinstance(claims.get("role"), str) or not isinstance(caps, list):
        raise TokenError("token is missing role or capabilities")

    # Imported here so that creating test tokens does not need a database connection.
    import revocation
    try:
        revoked = revocation.is_revoked(claims["jti"])
    except Exception:  # noqa: BLE001  cannot check -> treat as denied (fail closed)
        raise TokenError("cannot check revocation status")
    if revoked:
        raise TokenError("token has been revoked")
    return claims
