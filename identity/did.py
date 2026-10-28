"""DID helpers: Ed25519 keys, DID strings and W3C-style DID Documents.

WHAT IS SIMPLIFIED (important for your report):
  - Real DIDs (e.g. did:web, did:ion) are resolved through a network or a blockchain.
    Here a DID is just a string "did:example:<name>" and the DID Document is stored
    in a local JSON file (see registry.py). There is NO blockchain.
  - The private key is stored as an unencrypted PEM file. A production system would
    keep it in a hardware module or a secrets manager.
The cryptography itself (Ed25519 signatures) is real.
"""
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

DID_PREFIX = "did:example:"


# ---------- small base64url helpers (JWK and JWT use base64url without "=") ----------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)  # put back the "=" that we removed
    return base64.urlsafe_b64decode(text + padding)


# ---------- keys ----------
def generate_private_key() -> Ed25519PrivateKey:
    """Create a brand-new Ed25519 private key (the public key is derived from it)."""
    return Ed25519PrivateKey.generate()


def private_key_to_pem(private_key: Ed25519PrivateKey) -> bytes:
    """Turn a private key into PEM text so we can save it in a .pem file."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # simplified: not encrypted
    )


def load_private_key_from_pem(pem: bytes) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("PEM file does not contain an Ed25519 private key")
    return key


def public_key_to_jwk(public_key: Ed25519PublicKey) -> dict:
    """Public key as a JWK (JSON Web Key): the standard JSON shape for a key."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}


def jwk_to_public_key(jwk: dict) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("Unsupported key type (only Ed25519 is allowed)")
    return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))


# ---------- DID and DID Document ----------
def make_did(name: str) -> str:
    """make_did('agent-a') -> 'did:example:agent-a'"""
    return DID_PREFIX + name


def build_did_document(did: str, public_key: Ed25519PublicKey) -> dict:
    """A W3C-style DID Document: who the DID is and which key proves it."""
    key_id = f"{did}#key-1"
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": did,
        "verificationMethod": [
            {
                "id": key_id,
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_key_to_jwk(public_key),
            }
        ],
        # "authentication" lists which keys may be used to prove "I am this DID".
        "authentication": [key_id],
    }


def get_authentication_key(did_document: dict) -> Ed25519PublicKey:
    """Find the public key that the DID Document lists under 'authentication'."""
    for key_id in did_document.get("authentication", []):
        for method in did_document.get("verificationMethod", []):
            if method.get("id") == key_id:
                return jwk_to_public_key(method["publicKeyJwk"])
    raise ValueError("DID Document has no usable authentication key")


# ---------- sign / verify ----------
def sign_message(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
    return private_key.sign(message)


def verify_signature(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    """True only if 'signature' was made over 'message' by the matching private key."""
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
