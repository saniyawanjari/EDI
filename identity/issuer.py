"""Credential issuer: signs Verifiable Credentials (as JWTs) for agents.

SIMPLIFIED: a W3C Verifiable Credential has many optional parts (@context, proof
formats, status lists). We use the common "VC as a JWT" shape with the essential
claims only. The issuer is also just a DID in our local registry.
"""
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt  # PyJWT

from identity import registry
from identity.did import (
    build_did_document,
    generate_private_key,
    get_authentication_key,
    load_private_key_from_pem,
    private_key_to_pem,
    public_key_to_jwk,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ISSUER_DID = "did:example:soc-issuer"
ISSUER_KEY_PATH = Path(os.getenv("ISSUER_KEY_PATH", PROJECT_ROOT / "issuer_key.pem"))


class CredentialError(Exception):
    """Raised when a credential is not acceptable. The message is the reason."""


def _load_or_create_issuer_key():
    """Load issuer_key.pem, or create it the first time. The file is git-ignored (*.pem)."""
    if ISSUER_KEY_PATH.exists():
        return load_private_key_from_pem(ISSUER_KEY_PATH.read_bytes())
    key = generate_private_key()
    ISSUER_KEY_PATH.write_bytes(private_key_to_pem(key))
    try:
        os.chmod(ISSUER_KEY_PATH, 0o600)  # owner-only (has little effect on Windows)
    except OSError:
        pass
    return key


def ensure_issuer_registered():
    """Make sure the issuer's DID Document (public key) is in the registry."""
    key = _load_or_create_issuer_key()
    existing = registry.resolve(ISSUER_DID)
    new_jwk = public_key_to_jwk(key.public_key())
    # Only (re)write the registry if the issuer is missing or its key changed.
    if existing is None or existing["verificationMethod"][0]["publicKeyJwk"] != new_jwk:
        registry.register_did(ISSUER_DID, build_did_document(ISSUER_DID, key.public_key()))
    return key


def issue_credential(agent_did: str, role: str, allowed_actions: list[str], days_valid: int = 30) -> str:
    """Create and sign a credential saying: 'agent_did has this role and these actions'."""
    key = ensure_issuer_registered()
    now = datetime.now(timezone.utc)
    claims = {
        "iss": ISSUER_DID,                           # who issued it
        "sub": agent_did,                            # who it is about
        "iat": now,                                  # issued at
        "exp": now + timedelta(days=days_valid),     # expires at
        "jti": str(uuid.uuid4()),                    # unique id (used for revocation)
        "vc": {
            "type": ["VerifiableCredential", "AgentRoleCredential"],
            "credentialSubject": {
                "id": agent_did,
                "role": role,
                "allowed_actions": allowed_actions,
            },
        },
    }
    # EdDSA = signature with the Ed25519 private key.
    return jwt.encode(claims, key, algorithm="EdDSA", headers={"kid": f"{ISSUER_DID}#key-1"})


def verify_credential(vc_jwt: str) -> dict:
    """Check signature, expiry, issuer and revocation. Returns the claims or raises CredentialError."""
    ensure_issuer_registered()
    issuer_document = registry.resolve(ISSUER_DID)
    if issuer_document is None:
        raise CredentialError("issuer is not registered")
    issuer_public_key = get_authentication_key(issuer_document)

    try:
        claims = jwt.decode(
            vc_jwt,
            issuer_public_key,
            algorithms=["EdDSA"],  # ONLY EdDSA: blocks the "alg: none" trick
            issuer=ISSUER_DID,     # only OUR issuer is trusted
            options={"require": ["exp", "iat", "sub", "iss", "jti"]},
        )
    except jwt.ExpiredSignatureError:
        raise CredentialError("credential expired")
    except jwt.InvalidIssuerError:
        raise CredentialError("credential was not issued by the trusted issuer")
    except jwt.InvalidTokenError:
        # Covers a bad signature (tampered or forged), broken format, missing claims...
        raise CredentialError("credential signature or format is invalid")

    # Check that the credential has the shape we expect.
    vc = claims.get("vc")
    if not isinstance(vc, dict) or not isinstance(vc.get("type"), list) \
            or "AgentRoleCredential" not in vc["type"]:
        raise CredentialError("not an AgentRoleCredential")
    subject = vc.get("credentialSubject")
    if (not isinstance(subject, dict)
            or subject.get("id") != claims["sub"]
            or not isinstance(subject.get("role"), str)
            or not isinstance(subject.get("allowed_actions"), list)):
        raise CredentialError("credential subject is malformed")

    # Revocation check. If we cannot read the revocation list, we DENY (fail closed).
    try:
        revoked = registry.is_revoked(claims["jti"])
    except Exception:
        raise CredentialError("cannot check revocation status")
    if revoked:
        raise CredentialError("credential has been revoked")

    return claims
