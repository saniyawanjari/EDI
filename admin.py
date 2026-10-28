"""Admin endpoints (x-admin-key): revoke, audit log, stats, chain check, agents, policy."""
import hmac
import json
from pathlib import Path

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

import audit
import enforcement
import revocation
import soc_tools
from config import settings
from identity.issuer import CredentialError, verify_credential

import os

PROJECT_ROOT = Path(__file__).resolve().parent
AGENTS_DIR = Path(os.getenv("AGENTS_DIR", PROJECT_ROOT / "agents"))
POLICY_FILE = PROJECT_ROOT / "policy.rego"


def require_admin(x_admin_key: str | None = Header(default=None)) -> None:
    """Fail closed: no configured key, no header or a wrong key -> 403."""
    if not settings.admin_key or not x_admin_key or not hmac.compare_digest(x_admin_key, settings.admin_key):
        raise HTTPException(403, "admin key missing or invalid")


router = APIRouter(dependencies=[Depends(require_admin)], tags=["admin"])


class RevokeRequest(BaseModel):
    jti: str


@router.post("/api/v1/admin/revoke")
def revoke(body: RevokeRequest):
    revocation.revoke(body.jti)
    return {"revoked": body.jti}


@router.post("/api/v1/admin/reset-state")
def reset_state():
    """DEV/EVAL ONLY: clears the rate-limit window and the simulated SOC. Never touches the audit log."""
    enforcement.rate_window.reset()
    soc_tools.reset()
    return {"reset": True}


@router.get("/api/v1/audit")
def get_audit(decision: str | None = None, agent: str | None = None, limit: int = 50):
    if decision is not None and decision not in ("ALLOW", "DENY", "ERROR"):
        raise HTTPException(422, "decision must be ALLOW, DENY or ERROR")
    return audit.query_rows(decision, agent, limit)


@router.get("/api/v1/audit/stats")
def get_stats():
    return audit.stats()


@router.get("/api/v1/audit/verify-chain")
def verify_chain():
    return audit.verify_chain()


@router.get("/api/v1/policy")
def get_policy():
    return {"policy": POLICY_FILE.read_text(encoding="utf-8")}


# ------------------------------------------------------------------ agents
def sync_agents_from_disk() -> None:
    """Copy agents/*/agent.json into the agents table (public info only, never keys)."""
    for info_file in AGENTS_DIR.glob("*/agent.json"):
        try:
            info = json.loads(info_file.read_text())
            audit.upsert_agent(info["did"], info["role"])
        except (OSError, ValueError, KeyError):
            continue


def _credential_status(did: str) -> str:
    for info_file in AGENTS_DIR.glob("*/agent.json"):
        try:
            if json.loads(info_file.read_text()).get("did") == did:
                verify_credential((info_file.parent / "credential.jwt").read_text().strip())
                return "valid"
        except CredentialError as e:
            return str(e)
        except (OSError, ValueError):
            return "unreadable"
    return "unknown"


@router.get("/api/v1/agents")
def list_agents():
    sync_agents_from_disk()
    from db import SessionLocal
    from models import Agent
    from sqlalchemy import select

    result = []
    with SessionLocal() as session:
        agents = session.execute(select(Agent).order_by(Agent.role)).scalars().all()
    for agent in agents:
        last = audit.query_rows(agent=agent.did, limit=1)
        result.append({
            "did": agent.did,
            "role": agent.role,
            "status": agent.status,
            "credential_status": _credential_status(agent.did),
            "last_action": ({"timestamp": last[0]["timestamp"], "action": last[0]["action"],
                             "resource": last[0]["resource"], "decision": last[0]["decision"]}
                            if last else None),
        })
    return result
