"""DEV ONLY - attack/normal-flow simulator for the dashboard (Phase 6).

!!! This router can mint special tokens (expired, forged) and uses the stored agent
!!! private keys. NEVER ship it to production. It is protected by x-admin-key, and it
!!! exists only so you can click a button and watch the real enforcement pipeline react.

Every step is a REAL HTTP call to this same API, so every step creates real audit rows.
"""
from datetime import datetime, timedelta, timezone

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException

import client_lib
import tokens
from admin import require_admin
from config import settings
from identity.did import generate_private_key

router = APIRouter(prefix="/api/v1/demo", tags=["demo (dev only)"], dependencies=[Depends(require_admin)])

BLOCK = "/api/v1/agent-c/block"
PROTECTED_IP = "192.168.1.1"


class Runner:
    """Collects the steps of one scenario."""

    def __init__(self):
        self.base = settings.self_url
        self.http = httpx.Client(timeout=10)
        self.steps: list[dict] = []

    def step(self, title: str, method: str, path: str, token: str | None, body: dict | None = None,
             expect: str = "") -> httpx.Response:
        r = client_lib.call(self.base, method, path, token=token, json_body=body, client=self.http)
        try:
            data = r.json()
        except ValueError:
            data = {}
        detail = data.get("detail") if isinstance(data, dict) else None
        self.steps.append({
            "step": len(self.steps) + 1,
            "title": title,
            "request": f"{method} {path}" + (f" {body}" if body else ""),
            "status": r.status_code,
            "decision": "ALLOW" if r.status_code == 200 else ("ERROR" if r.status_code == 503 else "DENY"),
            "detail": detail or (str(data)[:200] if data else ""),
            "expected": expect,
            "decision_ms": r.headers.get("X-Decision-Time-ms"),
        })
        return r

    def token(self, role: str, **kwargs) -> str:
        return client_lib.get_token(client_lib.load_agent(role), self.base, client=self.http, **kwargs)


def normal_flow(run: Runner):
    ta = run.token("log_analyst")
    report = run.step("Agent A reads the logs", "GET", "/api/v1/agent-a/report", ta, expect="ALLOW").json()
    tb = run.token("threat_detector")
    threats = run.step("Agent B ranks the threats", "GET", "/api/v1/agent-b/threats", tb, expect="ALLOW").json()
    tc = run.token("incident_responder")
    for threat in threats.get("threats", []):
        run.step(f"Agent C blocks {threat['ip']} ({threat['severity']})", "POST", BLOCK, tc,
                 {"ip": threat["ip"]}, expect="ALLOW")
    return f"A found {len(report.get('report', {}))} suspicious IPs, B ranked them, C blocked the medium/high ones."


def analyst_blocks_ip(run: Runner):
    ta = run.token("log_analyst")
    run.step("Log Analyst tries to block an IP", "POST", BLOCK, ta, {"ip": "203.0.113.5"}, expect="DENY")
    return "The analyst may SUGGEST a block but has no authority to EXECUTE it."


def expired_token(run: Runner):
    agent = client_lib.load_agent("incident_responder")
    old = tokens.issue_token(client_lib.local_identity(agent), ttl_seconds=-60)
    run.step("Agent C uses an expired token", "POST", BLOCK, old, {"ip": "198.51.100.9"}, expect="DENY")
    return "Expired tokens are rejected (401)."


def forged_token(run: Runner):
    now = datetime.now(timezone.utc)
    claims = {"iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "sub": "did:example:agent-c",
              "role": "incident_responder", "jti": "forged-1", "iat": now, "exp": now + timedelta(minutes=5),
              "capabilities": [{"action": "block_ip", "resource": "ip:*"}]}
    fake = jwt.encode(claims, generate_private_key(), algorithm="EdDSA")  # attacker's own key
    run.step("Attacker uses a token signed with their own key", "POST", BLOCK, fake,
             {"ip": "198.51.100.10"}, expect="DENY")
    return "A forged token fails the signature check (401)."


def revoked_token(run: Runner):
    tc = run.token("incident_responder")
    run.step("Agent C blocks an IP with a fresh token", "POST", BLOCK, tc, {"ip": "198.51.100.11"}, expect="ALLOW")
    jti = jwt.decode(tc, options={"verify_signature": False})["jti"]
    import revocation
    revocation.revoke(jti)
    run.steps.append({"step": len(run.steps) + 1, "title": "Admin revokes the token", "request": f"revoke {jti}",
                      "status": 200, "decision": "ALLOW", "detail": "token added to revoked_tokens",
                      "expected": "", "decision_ms": None})
    run.step("Agent C replays the same token", "POST", BLOCK, tc, {"ip": "198.51.100.12"}, expect="DENY")
    return "After revocation the same token is rejected (401)."


def protected_ip(run: Runner):
    tc = run.token("incident_responder")
    run.step("Agent C tries to block the protected gateway", "POST", BLOCK, tc, {"ip": PROTECTED_IP}, expect="DENY")
    return "Protected assets override every allow rule (403)."


SCENARIOS = {
    "normal_flow": normal_flow,
    "analyst_blocks_ip": analyst_blocks_ip,
    "expired_token": expired_token,
    "forged_token": forged_token,
    "revoked_token": revoked_token,
    "protected_ip": protected_ip,
}


@router.post("/run/{scenario}")
def run_scenario(scenario: str):
    function = SCENARIOS.get(scenario)
    if function is None:
        raise HTTPException(404, f"unknown scenario. Choose one of: {', '.join(SCENARIOS)}")
    runner = Runner()
    try:
        summary = function(runner)
    except (RuntimeError, httpx.HTTPError, SystemExit) as e:
        raise HTTPException(500, f"scenario failed: {e}. Did you run scripts/create_agents.py?")
    return {"scenario": scenario, "summary": summary, "steps": runner.steps}
