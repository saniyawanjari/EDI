"""Phase 5 tests: every decision creates exactly ONE audit row; the hash chain detects edits.

Run:  pytest tests/test_audit.py -v      (the 200 test needs OPA running, the others do not)
"""
from sqlalchemy import func, select, update

from config import settings
from db import SessionLocal
from helpers import ADMIN, bearer, get_token, needs_opa
from models import AuditLog

REPORT = "/api/v1/agent-a/report"
BLOCK = "/api/v1/agent-c/block"


def count_rows() -> int:
    with SessionLocal() as session:
        return session.scalar(select(func.count(AuditLog.id)))


def last_row() -> AuditLog:
    with SessionLocal() as session:
        return session.execute(select(AuditLog).order_by(AuditLog.id.desc()).limit(1)).scalar_one()


def test_401_creates_one_row(client):
    before = count_rows()
    r = client.get(REPORT)
    assert r.status_code == 401
    assert count_rows() == before + 1
    row = last_row()
    assert (row.decision, row.http_status) == ("DENY", 401)
    assert row.reason
    assert "x-decision-time-ms" in r.headers


def test_403_creates_one_row(client, agents):
    token = get_token(client, agents["log_analyst"])
    before = count_rows()
    assert client.post(BLOCK, json={"ip": "10.0.0.5"}, headers=bearer(token)).status_code == 403
    assert count_rows() == before + 1
    row = last_row()
    assert (row.decision, row.http_status) == ("DENY", 403)
    assert row.agent_did == agents["log_analyst"]["did"]
    assert row.reason


def test_503_creates_one_row(client, agents, monkeypatch):
    token = get_token(client, agents["log_analyst"])
    monkeypatch.setattr(settings, "opa_url", "http://127.0.0.1:9/v1/data/authz/allow")  # nothing listens here
    before = count_rows()
    r = client.get(REPORT, headers=bearer(token))
    assert r.status_code == 503  # fail closed
    assert count_rows() == before + 1
    row = last_row()
    assert (row.decision, row.http_status) == ("ERROR", 503)
    assert row.reason


@needs_opa
def test_200_creates_one_row(client, agents):
    token = get_token(client, agents["log_analyst"])
    before = count_rows()
    assert client.get(REPORT, headers=bearer(token)).status_code == 200
    assert count_rows() == before + 1
    row = last_row()
    assert (row.decision, row.http_status) == ("ALLOW", 200)
    assert row.opa_ms is not None and row.token_verify_ms is not None and row.token_jti


def test_admin_audit_endpoints(client, agents):
    client.get(REPORT)  # make sure at least one row exists
    rows = client.get("/api/v1/audit?decision=DENY&limit=5", headers=ADMIN).json()
    assert rows and all(r["decision"] == "DENY" for r in rows)
    stats = client.get("/api/v1/audit/stats", headers=ADMIN).json()
    assert stats["total"] >= 1 and stats["denied"] >= 1
    assert client.get("/api/v1/audit?decision=MAYBE", headers=ADMIN).status_code == 422


def test_hash_chain_detects_editing(client):
    for _ in range(3):
        client.get(REPORT)  # three more rows
    assert client.get("/api/v1/audit/verify-chain", headers=ADMIN).json()["valid"] is True

    target = last_row()
    original = target.reason
    with SessionLocal() as session:  # someone edits a row directly in the database
        session.execute(update(AuditLog).where(AuditLog.id == target.id).values(reason="nothing happened"))
        session.commit()
    try:
        result = client.get("/api/v1/audit/verify-chain", headers=ADMIN).json()
        assert result["valid"] is False
        assert result["first_broken_id"] == target.id
    finally:  # put it back so other tests see a valid chain
        with SessionLocal() as session:
            session.execute(update(AuditLog).where(AuditLog.id == target.id).values(reason=original))
            session.commit()
    assert client.get("/api/v1/audit/verify-chain", headers=ADMIN).json()["valid"] is True
