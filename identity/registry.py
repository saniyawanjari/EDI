"""Local DID registry (a JSON file) + the revoked-credential list.

SIMPLIFIED: a real DID registry would be a blockchain or a web service. Here it is
just registry.json next to main.py. Revocation is stored here too for Phase 3;
a later phase moves revocation into the database.
"""
import json
import os
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = Path(os.getenv("REGISTRY_PATH", PROJECT_ROOT / "registry.json"))

_lock = threading.Lock()  # FastAPI can run several requests at once; protect the file


def _load() -> dict:
    if not REGISTRY_PATH.exists():
        return {"did_documents": {}, "revoked_credentials": []}
    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(data: dict) -> None:
    # Write to a temp file first, then swap it in, so a crash cannot corrupt the registry.
    tmp_path = REGISTRY_PATH.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp_path, REGISTRY_PATH)


def register_did(did: str, did_document: dict) -> None:
    with _lock:
        data = _load()
        data["did_documents"][did] = did_document
        _save(data)


def resolve(did: str) -> dict | None:
    """Return the DID Document for this DID, or None if the DID is unknown."""
    with _lock:
        return _load()["did_documents"].get(did)


def revoke_credential(jti: str) -> None:
    """Mark a credential (by its unique id 'jti') as revoked."""
    with _lock:
        data = _load()
        if jti not in data["revoked_credentials"]:
            data["revoked_credentials"].append(jti)
        _save(data)


def is_revoked(jti: str) -> bool:
    with _lock:
        return jti in _load()["revoked_credentials"]


# ---------- API: public lookup of a DID Document ----------
router = APIRouter(prefix="/api/v1/did", tags=["identity"])


@router.get("/{did}")
def get_did_document(did: str):
    document = resolve(did)
    if document is None:
        raise HTTPException(status_code=404, detail="DID not found")
    return document
