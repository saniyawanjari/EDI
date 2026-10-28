"""Phase 4 tests: capability tokens and the enforcement pipeline.

Run:  pytest tests/test_tokens.py -v
Tests marked needs_opa use the REAL policy.rego: start OPA first (they skip themselves otherwise).
"""
from datetime import datetime, timedelta, timezone

import jwt

import tokens
from helpers import ADMIN, bearer, get_token, identity_for, needs_opa
from identity.did import generate_private_key

REPORT = "/api/v1/agent-a/report"
BLOCK = "/api/v1/agent-c/block"


def test_no_token_is_401(client):
    assert client.get(REPORT).status_code == 401


def test_malformed_header_is_401(client):
    assert client.get(REPORT, headers={"Authorization": "Token abc"}).status_code == 401


def test_forged_token_is_401(client):
    now = datetime.now(timezone.utc)
    claims = {"iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "sub": "did:example:agent-c",
              "role": "incident_responder", "jti": "x", "iat": now, "exp": now + timedelta(minutes=5),
              "capabilities": [{"action": "block_ip", "resource": "ip:*"}]}
    fake = jwt.encode(claims, generate_private_key(), algorithm="EdDSA")  # attacker's key
    r = client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(fake))
    assert r.status_code == 401


def test_expired_token_is_401(client, agents):
    old = tokens.issue_token(identity_for(agents["incident_responder"]), ttl_seconds=-60)
    r = client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(old))
    assert r.status_code == 401
    assert "expired" in r.json()["detail"]


def test_revoked_token_is_401(client, agents):
    token = get_token(client, agents["incident_responder"])
    jti = jwt.decode(token, options={"verify_signature": False})["jti"]
    assert client.post("/api/v1/admin/revoke", json={"jti": jti}, headers=ADMIN).status_code == 200
    r = client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(token))
    assert r.status_code == 401
    assert "revoked" in r.json()["detail"]


def test_wrong_action_is_403(client, agents):
    """The Log Analyst token has no block_ip capability."""
    token = get_token(client, agents["log_analyst"])
    r = client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(token))
    assert r.status_code == 403
    assert "capability" in r.json()["detail"]


def test_role_header_is_ignored(client, agents):
    token = get_token(client, agents["log_analyst"])
    headers = {**bearer(token), "x-agent-role": "incident_responder"}  # spoofing attempt
    assert client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=headers).status_code == 403


def test_narrow_token_works_for_one_resource_only(client, agents):
    scope = [{"action": "block_ip", "resource": "ip:10.0.0.5"}]
    token = get_token(client, agents["incident_responder"], capabilities=scope)
    r = client.post(BLOCK, json={"ip": "10.0.0.9"}, headers=bearer(token))  # a different IP
    assert r.status_code == 403


def test_agent_cannot_request_more_than_its_credential_allows(client, agents):
    from helpers import identity_for  # noqa: F401
    from identity.did import b64url_encode, sign_message

    agent = agents["log_analyst"]
    nonce = client.post("/api/v1/auth/challenge", json={"did": agent["did"]}).json()["nonce"]
    body = {"did": agent["did"], "vc_jwt": agent["vc"],
            "signature": b64url_encode(sign_message(agent["key"], nonce.encode())),
            "capabilities": [{"action": "block_ip", "resource": "ip:*"}]}
    assert client.post("/api/v1/token", json=body).status_code == 403


def test_admin_endpoints_need_the_key(client):
    assert client.post("/api/v1/admin/revoke", json={"jti": "x"}).status_code == 403
    assert client.get("/api/v1/audit").status_code == 403


@needs_opa
def test_correct_request_is_200(client, agents):
    token = get_token(client, agents["log_analyst"])
    r = client.get(REPORT, headers=bearer(token))
    assert r.status_code == 200
    assert "x-decision-time-ms" in r.headers
    assert r.json()["report"]  # at least one suspicious IP


@needs_opa
def test_blocked_ip_shows_up_in_soc(client, agents):
    token = get_token(client, agents["incident_responder"])
    assert client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(token)).status_code == 200
    assert "10.0.0.5" in client.get("/api/v1/soc/blocked").json()["blocked_ips"]


@needs_opa
def test_protected_ip_is_403(client, agents):
    token = get_token(client, agents["incident_responder"])
    for sneaky in ["192.168.1.1", " 192.168.1.1 ", "::ffff:192.168.1.1"]:
        r = client.post(BLOCK, json={"ip": sneaky}, headers=bearer(token))
        assert r.status_code == 403, sneaky
        assert "protected" in r.json()["detail"]


@needs_opa
def test_protected_host_is_403(client, agents):
    token = get_token(client, agents["incident_responder"])
    for name in ["db-01", "DB-01"]:
        assert client.post("/api/v1/agent-c/isolate", json={"host": name},
                           headers=bearer(token)).status_code == 403


@needs_opa
def test_sixth_block_in_a_minute_is_403(client, agents):
    token = get_token(client, agents["incident_responder"])
    for i in range(5):
        r = client.post(BLOCK, json={"ip": f"10.1.0.{i + 1}"}, headers=bearer(token))
        assert r.status_code == 200, r.text
    r = client.post(BLOCK, json={"ip": "10.1.0.6"}, headers=bearer(token))
    assert r.status_code == 403
    assert "rate limit" in r.json()["detail"]
