"""Phase 3 tests: valid identity passes; every kind of bad identity fails.

Run from the project root:   pytest tests/test_identity.py -v
Each test uses temporary files, so your real agents/ and registry.json are untouched.
"""
import base64
import json

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from identity import auth, issuer, registry
from identity.did import (
    b64url_encode,
    build_did_document,
    generate_private_key,
    sign_message,
)


@pytest.fixture(autouse=True)
def isolated_files(tmp_path, monkeypatch):
    """Point the registry and issuer key at temp files and clear old nonces."""
    monkeypatch.setattr(registry, "REGISTRY_PATH", tmp_path / "registry.json")
    monkeypatch.setattr(issuer, "ISSUER_KEY_PATH", tmp_path / "issuer_key.pem")
    auth._nonces.clear()


def make_agent(name="agent-a", role="log_analyst", actions=("read_logs",), days_valid=30):
    """Create a registered agent. Returns (did, private_key, credential_jwt)."""
    did = f"did:example:{name}"
    key = generate_private_key()
    registry.register_did(did, build_did_document(did, key.public_key()))
    vc = issuer.issue_credential(did, role, list(actions), days_valid=days_valid)
    return did, key, vc


def prove(did, signing_key, vc):
    """Do challenge -> sign -> verify with the logic functions. Returns the identity."""
    nonce = auth.create_challenge(did)
    signature = b64url_encode(sign_message(signing_key, nonce.encode()))
    return auth.authenticate_agent(did, signature, vc)


def test_valid_agent_passes():
    did, key, vc = make_agent()
    identity = prove(did, key, vc)
    assert identity["did"] == did
    assert identity["role"] == "log_analyst"
    assert identity["allowed_actions"] == ["read_logs"]


def test_wrong_key_fails():
    did, _real_key, vc = make_agent()
    attacker_key = generate_private_key()  # attacker does not own the real key
    with pytest.raises(auth.AuthError, match="signature"):
        prove(did, attacker_key, vc)


def test_tampered_vc_fails():
    did, key, vc = make_agent()
    header, payload, signature = vc.split(".")
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded))
    claims["vc"]["credentialSubject"]["role"] = "incident_responder"  # privilege escalation!
    claims["vc"]["credentialSubject"]["allowed_actions"] = ["block_ip"]
    new_payload = b64url_encode(json.dumps(claims).encode())
    tampered = f"{header}.{new_payload}.{signature}"  # old signature no longer matches
    with pytest.raises(auth.AuthError, match="invalid"):
        prove(did, key, tampered)


def test_expired_vc_fails():
    did, key, vc = make_agent(days_valid=-1)  # already expired yesterday
    with pytest.raises(auth.AuthError, match="expired"):
        prove(did, key, vc)


def test_revoked_vc_fails():
    did, key, vc = make_agent()
    jti = issuer.verify_credential(vc)["jti"]
    registry.revoke_credential(jti)
    with pytest.raises(auth.AuthError, match="revoked"):
        prove(did, key, vc)


def test_reused_nonce_fails():
    did, key, vc = make_agent()
    nonce = auth.create_challenge(did)
    signature = b64url_encode(sign_message(key, nonce.encode()))
    auth.authenticate_agent(did, signature, vc)  # first use works
    with pytest.raises(auth.AuthError, match="already used"):
        auth.authenticate_agent(did, signature, vc)  # replay is rejected


def test_expired_nonce_fails():
    did, key, vc = make_agent()
    nonce = auth.create_challenge(did)
    auth._nonces[did] = (nonce, 0.0)  # pretend the 60 seconds are over
    signature = b64url_encode(sign_message(key, nonce.encode()))
    with pytest.raises(auth.AuthError, match="expired"):
        auth.authenticate_agent(did, signature, vc)


def test_credential_of_another_agent_fails():
    did_a, _key_a, vc_a = make_agent("agent-a", "log_analyst", ["read_logs"])
    did_c, key_c, _vc_c = make_agent("agent-c", "incident_responder", ["block_ip"])
    # Agent C owns its own key but presents Agent A's credential.
    with pytest.raises(auth.AuthError, match="different DID"):
        prove(did_c, key_c, vc_a)


# ---------- a few tests through the real HTTP endpoints ----------
def make_client():
    app = FastAPI()
    app.include_router(registry.router)
    app.include_router(auth.router)
    return TestClient(app)


def test_http_valid_flow_and_did_lookup():
    did, key, vc = make_agent()
    client = make_client()

    assert client.get(f"/api/v1/did/{did}").json()["id"] == did
    assert client.get("/api/v1/did/did:example:nobody").status_code == 404

    nonce = client.post("/api/v1/auth/challenge", json={"did": did}).json()["nonce"]
    signature = b64url_encode(sign_message(key, nonce.encode()))
    r = client.post("/api/v1/auth/verify", json={"did": did, "signature": signature, "vc_jwt": vc})
    assert r.status_code == 200
    assert r.json() == {"did": did, "role": "log_analyst", "allowed_actions": ["read_logs"]}


def test_http_bad_proof_returns_401_with_reason():
    did, _key, vc = make_agent()
    client = make_client()
    client.post("/api/v1/auth/challenge", json={"did": did})
    bad_signature = b64url_encode(sign_message(generate_private_key(), b"whatever"))
    r = client.post("/api/v1/auth/verify", json={"did": did, "signature": bad_signature, "vc_jwt": vc})
    assert r.status_code == 401
    assert "signature" in r.json()["detail"]
