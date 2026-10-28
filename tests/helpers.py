"""Small helpers shared by the Phase 4 and Phase 5 tests."""
import httpx
import pytest

from config import settings
from identity import auth
from identity.did import b64url_encode, sign_message

ADMIN = {"x-admin-key": "test-admin-key"}  # matches ADMIN_KEY set in conftest.py


def opa_available() -> bool:
    try:
        return httpx.post(settings.opa_url, json={"input": {}}, timeout=1.5).status_code == 200
    except httpx.HTTPError:
        return False


# Tests that need the REAL policy skip themselves when OPA is not running.
needs_opa = pytest.mark.skipif(not opa_available(), reason="OPA is not running (start it, see README)")


def get_token(client, agent: dict, capabilities=None) -> str:
    """challenge -> sign -> POST /token, like a real agent would."""
    nonce = client.post("/api/v1/auth/challenge", json={"did": agent["did"]}).json()["nonce"]
    signature = b64url_encode(sign_message(agent["key"], nonce.encode()))
    body = {"did": agent["did"], "signature": signature, "vc_jwt": agent["vc"]}
    if capabilities is not None:
        body["capabilities"] = capabilities
    response = client.post("/api/v1/token", json=body)
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def identity_for(agent: dict) -> dict:
    """Identity proof in-process (used to craft special tokens such as expired ones)."""
    nonce = auth.create_challenge(agent["did"])
    signature = b64url_encode(sign_message(agent["key"], nonce.encode()))
    return auth.authenticate_agent(agent["did"], signature, agent["vc"])


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}
