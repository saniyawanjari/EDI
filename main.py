"""SOC Agent Supervisor - FastAPI app (final version, Phases 1-7).

Every action goes through enforce(): identity -> capability token -> OPA -> audit log.
The old x-agent-role header is NOT used any more (except by the weak evaluation baselines).
"""
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import agent_a
import agent_b
import agent_c
import audit
import soc_tools
import tokens
from admin import router as admin_router, sync_agents_from_disk
from config import settings
from db import init_db
from demo import router as demo_router
from enforcement import Decision, enforce, fixed_resource, host_resource, ip_resource
from identity.auth import AuthError, authenticate_agent, router as auth_router
from identity.registry import router as did_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()                # create tables
    sync_agents_from_disk()  # fill the agents table from agents/*/agent.json
    tokens.get_server_key()  # make sure server_key.pem exists
    yield


app = FastAPI(title="SOC Agent Supervisor", version="final", lifespan=lifespan)

# CORS: only the dashboard origin may call us from a browser.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.cors_origin, "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Decision-Time-ms", "X-Token-Verify-ms", "X-OPA-ms", "X-Request-ID"],
)

app.include_router(did_router)    # Phase 3: GET /api/v1/did/{did}
app.include_router(auth_router)   # Phase 3: challenge / verify
app.include_router(admin_router)  # Phase 4-6: revoke, audit, stats, agents, policy (x-admin-key)
app.include_router(demo_router)   # Phase 6: DEV ONLY simulator (x-admin-key)


@app.get("/health")
def health():
    return {"status": "ok", "security_mode": settings.security_mode}


# ------------------------------------------------------------------ Phase 4: tokens
class CapabilityIn(BaseModel):
    action: str
    resource: str


class TokenRequest(BaseModel):
    did: str
    signature: str  # base64url signature of the nonce from /auth/challenge
    vc_jwt: str
    capabilities: list[CapabilityIn] | None = None  # optional: ask for LESS than allowed


@app.post("/api/v1/token")
def issue_token(body: TokenRequest):
    """Prove identity (Phase 3 proof) and receive a 5-minute capability token."""
    t0 = time.perf_counter()
    info = {"request_id": uuid.uuid4().hex, "agent_did": body.did, "role": None,
            "action": "issue_token", "resource": "token", "token_jti": None}

    def record(decision: str, status: int, reason: str) -> dict:
        total = (time.perf_counter() - t0) * 1000
        try:
            audit.write_audit(**info, decision=decision, reason=reason, http_status=status, latency_ms=total)
        except Exception as e:  # noqa: BLE001
            if status == 200:
                raise HTTPException(503, "audit log unavailable - no token issued")
            print(f"WARNING: audit write failed: {e!r}")
        return {"X-Decision-Time-ms": f"{total:.3f}"}

    try:
        identity = authenticate_agent(body.did, body.signature, body.vc_jwt)
        info["role"] = identity["role"]
        requested = [c.model_dump() for c in body.capabilities] if body.capabilities is not None else None
        access_token = tokens.issue_token(identity, requested)
    except AuthError as e:
        raise HTTPException(401, str(e), headers=record("DENY", 401, f"identity proof failed: {e}"))
    except tokens.ScopeError as e:
        raise HTTPException(403, str(e), headers=record("DENY", 403, str(e)))
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        raise HTTPException(503, "token service error", headers=record("ERROR", 503, "token service error"))

    record("ALLOW", 200, "capability token issued")
    return {"access_token": access_token, "token_type": "bearer", "expires_in": tokens.TOKEN_TTL_SECONDS}


# ------------------------------------------------------------------ agents
class BlockRequest(BaseModel):
    ip: str


class IsolateRequest(BaseModel):
    host: str


@app.get("/api/v1/agent-a/report")
def agent_a_report(decision: Decision = Depends(enforce("read_logs", fixed_resource("server_logs.txt")))):
    report = agent_a.run_analysis()  # runs ONLY if enforce() allowed it
    return {"agent": "log_analyst", "threshold": agent_a.THRESHOLD, "report": report}


@app.get("/api/v1/agent-b/threats")
def agent_b_threats(decision: Decision = Depends(enforce("report_threat", fixed_resource("threat_report")))):
    # Agent B works on Agent A's analysis of the logs.
    threats = agent_b.analyze(agent_a.run_analysis())
    return {"agent": "threat_detector", "threats": threats}


@app.post("/api/v1/agent-c/block")
def agent_c_block(body: BlockRequest, decision: Decision = Depends(enforce("block_ip", ip_resource))):
    ip = decision.resource.split(":", 1)[1]  # the CHECKED, canonical IP (not the raw input)
    return {"agent": "incident_responder", "result": agent_c.execute_block(ip)}


@app.post("/api/v1/agent-c/isolate")
def agent_c_isolate(body: IsolateRequest, decision: Decision = Depends(enforce("isolate_host", host_resource))):
    host = decision.resource.split(":", 1)[1]
    return {"agent": "incident_responder", "result": agent_c.execute_isolate(host)}


@app.get("/api/v1/soc/blocked")
def soc_blocked():
    """Read-only view of the simulated SOC state. No auth, no secrets."""
    return {"blocked_ips": soc_tools.list_blocked(), "isolated_hosts": soc_tools.list_isolated()}
