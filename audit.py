"""Audit log with a tamper-evident hash chain (Phase 5).

Every row stores prev_hash (the hash of the row before it) and row_hash
(SHA-256 over its own fields + prev_hash). Change or delete any old row and the
chain breaks, so verify_chain() can tell. LIMITATION: deleting the LAST rows
cannot be detected without an external anchor (e.g. printing the latest hash).
"""
import hashlib
import json
import threading
from datetime import datetime, timezone

from sqlalchemy import func, select

from db import SessionLocal
from models import Agent, AuditLog

GENESIS_HASH = "0" * 64  # fixed value used as prev_hash for the very first row

# The fields that go into the hash, in this exact order.
HASH_FIELDS = [
    "timestamp", "request_id", "agent_did", "role", "action", "resource", "decision",
    "reason", "http_status", "latency_ms", "token_verify_ms", "opa_ms", "token_jti",
]

# Only one writer at a time, so "read last hash + insert new row" cannot interleave.
_chain_lock = threading.Lock()


def compute_row_hash(fields: dict, prev_hash: str) -> str:
    values = [fields[name] for name in HASH_FIELDS] + [prev_hash]
    text = json.dumps(values, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _round(value):
    return None if value is None else round(float(value), 3)


def write_audit(*, request_id, agent_did, role, action, resource, decision, reason,
                http_status, latency_ms, token_verify_ms=None, opa_ms=None, token_jti=None) -> int:
    """Append one row. Called on EVERY path (200, 401, 403, 422, 503). Returns the row id."""
    fields = {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
        "request_id": request_id,
        "agent_did": agent_did,
        "role": role,
        "action": action,
        "resource": resource[:300] if resource else resource,
        "decision": decision,
        "reason": (reason or "no reason recorded")[:500],
        "http_status": int(http_status),
        "latency_ms": _round(latency_ms),
        "token_verify_ms": _round(token_verify_ms),
        "opa_ms": _round(opa_ms),
        "token_jti": token_jti,
    }
    with _chain_lock:
        with SessionLocal() as session:
            last_hash = session.execute(
                select(AuditLog.row_hash).order_by(AuditLog.id.desc()).limit(1)
            ).scalar()
            prev_hash = last_hash or GENESIS_HASH
            row = AuditLog(**fields, prev_hash=prev_hash, row_hash=compute_row_hash(fields, prev_hash))
            session.add(row)
            session.commit()
            return row.id


def verify_chain() -> dict:
    """Walk all rows in order. Returns the first broken row id (or None)."""
    expected_prev = GENESIS_HASH
    checked = 0
    with SessionLocal() as session:
        for row in session.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
            checked += 1
            if row.prev_hash != expected_prev:
                return {"valid": False, "rows_checked": checked, "first_broken_id": row.id,
                        "reason": "prev_hash does not match the row before (a row was deleted or reordered)"}
            fields = {name: getattr(row, name) for name in HASH_FIELDS}
            if compute_row_hash(fields, row.prev_hash) != row.row_hash:
                return {"valid": False, "rows_checked": checked, "first_broken_id": row.id,
                        "reason": "row content was modified after it was written"}
            expected_prev = row.row_hash
    return {"valid": True, "rows_checked": checked, "first_broken_id": None, "reason": None}


def row_to_dict(row: AuditLog) -> dict:
    return {c.name: getattr(row, c.name) for c in AuditLog.__table__.columns}


def query_rows(decision: str | None = None, agent: str | None = None, limit: int = 50) -> list[dict]:
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(max(1, min(limit, 1000)))
    if decision:
        stmt = stmt.where(AuditLog.decision == decision)
    if agent:
        stmt = stmt.where(AuditLog.agent_did == agent)
    with SessionLocal() as session:
        return [row_to_dict(r) for r in session.execute(stmt).scalars()]


def stats() -> dict:
    with SessionLocal() as session:
        total = session.scalar(select(func.count(AuditLog.id))) or 0
        by_decision = dict(session.execute(
            select(AuditLog.decision, func.count()).group_by(AuditLog.decision)).all())
        avg_latency = session.scalar(select(func.avg(AuditLog.latency_ms)))
        per_agent: dict = {}
        for did, decision, count in session.execute(
                select(AuditLog.agent_did, AuditLog.decision, func.count())
                .group_by(AuditLog.agent_did, AuditLog.decision)).all():
            entry = per_agent.setdefault(did or "(unauthenticated)",
                                         {"total": 0, "ALLOW": 0, "DENY": 0, "ERROR": 0})
            entry[decision] = count
            entry["total"] += count
    return {
        "total": total,
        "allowed": by_decision.get("ALLOW", 0),
        "denied": by_decision.get("DENY", 0),
        "errors": by_decision.get("ERROR", 0),
        "average_latency_ms": round(avg_latency, 3) if avg_latency is not None else 0.0,
        "per_agent": per_agent,
    }


# ---------- agents table ----------
def upsert_agent(did: str, role: str, status: str = "active") -> None:
    with SessionLocal() as session:
        agent = session.get(Agent, did)
        if agent is None:
            session.add(Agent(did=did, role=role, status=status,
                              created_at=datetime.now(timezone.utc).isoformat()))
        else:
            agent.role, agent.status = role, status
        session.commit()
