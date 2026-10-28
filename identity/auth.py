"""Proof of identity: challenge -> sign -> verify.

How it works:
  1. The agent asks for a challenge. The Supervisor invents a random nonce.
  2. The agent signs the nonce with its PRIVATE key (proves it owns the DID).
  3. The agent sends DID + signature + its credential. The Supervisor checks
     everything and answers who the agent is and what role it has.

SIMPLIFIED: nonces live in memory (lost on restart, one server only).
"""
import secrets
import threading
import time

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from identity import registry
from identity.did import b64url_decode, get_authentication_key, verify_signature
from identity.issuer import CredentialError, verify_credential

NONCE_TTL_SECONDS = 60

# did -> (nonce, expiry_time). Only the newest nonce per DID is kept.
_nonces: dict[str, tuple[str, float]] = {}
_nonce_lock = threading.Lock()


class AuthError(Exception):
    """Raised when identity proof fails. The message is the reason shown to the caller."""


def create_challenge(did: str) -> str:
    nonce = secrets.token_urlsafe(32)  # unguessable random string
    now = time.time()
    with _nonce_lock:
        # Clean out expired nonces so the dictionary cannot grow forever.
        for old_did in [d for d, (_, exp) in _nonces.items() if exp < now]:
            del _nonces[old_did]
        _nonces[did] = (nonce, now + NONCE_TTL_SECONDS)
    return nonce


def _take_nonce(did: str) -> str:
    """Get the nonce for this DID AND delete it (single use, even if the proof later fails)."""
    with _nonce_lock:
        entry = _nonces.pop(did, None)
    if entry is None:
        raise AuthError("no active challenge for this DID (nonce missing or already used)")
    nonce, expires_at = entry
    if time.time() > expires_at:
        raise AuthError("challenge expired")
    return nonce


def authenticate_agent(did: str, signature_b64: str, vc_jwt: str) -> dict:
    """Full identity check. Returns {did, role, allowed_actions} or raises AuthError.

    Phase 4 reuses this function when it hands out capability tokens.
    """
    # 1) a valid, unused, unexpired nonce must exist
    nonce = _take_nonce(did)

    # 2) the DID must be known
    did_document = registry.resolve(did)
    if did_document is None:
        raise AuthError("unknown DID")

    # 3) the nonce signature must match the key in the DID Document
    try:
        public_key = get_authentication_key(did_document)
        signature = b64url_decode(signature_b64)
    except (ValueError, KeyError):
        raise AuthError("DID Document or signature is malformed")
    if not verify_signature(public_key, signature, nonce.encode("utf-8")):
        raise AuthError("signature does not match the DID key (wrong private key)")

    # 4) the credential must be valid (signature, expiry, issuer, not revoked)
    try:
        claims = verify_credential(vc_jwt)
    except CredentialError as e:
        raise AuthError(str(e))

    # 5) the credential must belong to THIS DID (stops using someone else's credential)
    if claims["sub"] != did:
        raise AuthError("credential was issued to a different DID")

    subject = claims["vc"]["credentialSubject"]
    return {
        "did": did,
        "role": subject["role"],
        "allowed_actions": subject["allowed_actions"],
        "credential_jti": claims["jti"],  # Phase 4 puts this in the token
    }


# ---------- API ----------
router = APIRouter(prefix="/api/v1/auth", tags=["identity"])


class ChallengeRequest(BaseModel):
    did: str


class VerifyRequest(BaseModel):
    did: str
    signature: str  # base64url signature of the nonce
    vc_jwt: str


@router.post("/challenge")
def challenge(body: ChallengeRequest):
    if registry.resolve(body.did) is None:
        raise HTTPException(status_code=404, detail="unknown DID")
    return {"nonce": create_challenge(body.did), "expires_in": NONCE_TTL_SECONDS}


@router.post("/verify")
def verify(body: VerifyRequest):
    try:
        identity = authenticate_agent(body.did, body.signature, body.vc_jwt)
    except AuthError as e:
        raise HTTPException(status_code=401, detail=str(e))
    # Only return the three fields the spec asks for.
    return {
        "did": identity["did"],
        "role": identity["role"],
        "allowed_actions": identity["allowed_actions"],
    }
