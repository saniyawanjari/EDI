"""THE single enforcement point (Phase 4 + 5 + 7).

Every protected endpoint uses  Depends(enforce(action, resource_getter)).  In order it:
  1. reads the Bearer token                -> 401 if missing / malformed / forged / expired / revoked
  2. checks the token's capabilities       -> 403 if the action+resource is not inside the token
  3. asks OPA for the final decision       -> 403 if denied, 503 if OPA cannot be reached
  4. records the decision in the audit log (on EVERY path, also when denied)
Any unexpected problem means DENY, never allow (fail closed).
"""
import ipaddress
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass

import httpx
from fastapi import HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

import audit
import tokens
from config import settings


# ---------------------------------------------------------------- sliding window
class SlidingWindow:
    """Counts how often (agent, action) happened in the last N seconds (in memory)."""

    def __init__(self, seconds: int = 60):
        self.seconds = seconds
        self._events: dict[tuple, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _prune(self, key):
        events, limit = self._events[key], time.monotonic() - self.seconds
        while events and events[0] < limit:
            events.popleft()

    def count(self, did: str, action: str) -> int:
        with self._lock:
            self._prune((did, action))
            return len(self._events[(did, action)])

    def record(self, did: str, action: str) -> None:
        with self._lock:
            self._events[(did, action)].append(time.monotonic())

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


rate_window = SlidingWindow(60)


# ---------------------------------------------------------------- resource getters
# A getter turns the request into ONE canonical resource string, e.g. "ip:10.0.0.5".
# Canonical form matters: "::ffff:192.168.1.1" and " 192.168.1.1 " must not bypass the
# protected-IP rule, and "DB-01" must equal "db-01".
HOST_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")


async def _json_body(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        raise ValueError("request body must be valid JSON")
    if not isinstance(data, dict):
        raise ValueError("request body must be a JSON object")
    return data


def fixed_resource(resource: str):
    async def getter(request: Request) -> str:
        return resource
    return getter


async def ip_resource(request: Request) -> str:
    value = (await _json_body(request)).get("ip")
    if not isinstance(value, str):
        raise ValueError("field 'ip' (string) is required")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        raise ValueError("invalid IP address")
    if address.version == 6 and address.ipv4_mapped:  # "::ffff:1.2.3.4" is really 1.2.3.4
        address = address.ipv4_mapped
    return f"ip:{address}"


async def host_resource(request: Request) -> str:
    value = (await _json_body(request)).get("host")
    if not isinstance(value, str) or not HOST_PATTERN.match(value.strip()):
        raise ValueError("field 'host' must be a valid host name")
    return f"host:{value.strip().lower()}"


# ---------------------------------------------------------------- OPA
class OpaUnavailable(Exception):
    pass


# keep-alive disabled: a restarted OPA never leaves us with a dead pooled connection.
_opa_client = httpx.Client(timeout=2.0, limits=httpx.Limits(max_keepalive_connections=0))


def _opa_package_url() -> str:
    url = settings.opa_url.rstrip("/")
    # We ask for the whole package so we also get "deny_reasons", not only "allow".
    return url[: -len("/allow")] if url.endswith("/allow") else url


def query_opa(opa_input: dict) -> dict:
    try:
        response = _opa_client.post(_opa_package_url(), json={"input": opa_input})
        response.raise_for_status()
        result = response.json().get("result")
    except (httpx.HTTPError, ValueError) as e:
        raise OpaUnavailable(e.__class__.__name__)
    if not isinstance(result, dict):
        raise OpaUnavailable("policy not loaded")
    return result


# ---------------------------------------------------------------- baseline modes (Phase 7)
# These two weak modes exist ONLY so the evaluation can show how much our protections add.
# They must never be used for real. "full" is the default and the only safe mode.
BASELINE_PERMISSIONS = {   # keep in sync with policy.rego (used by header_only only)
    "log_analyst": {"read_logs"},
    "threat_detector": {"read_logs", "report_threat"},
    "incident_responder": {"block_ip", "isolate_host"},
}
BASELINE_PROTECTED = {"ip:192.168.1.1", "host:db-01"}


# ---------------------------------------------------------------- the dependency
@dataclass
class Decision:
    request_id: str
    did: str | None
    role: str | None
    action: str
    resource: str | None
    token_jti: str | None


def _ms(start: float) -> float:
    return (time.perf_counter() - start) * 1000


def enforce(action: str, resource_getter):
    """Build a FastAPI dependency that guards one action."""

    async def dependency(request: Request, response: Response) -> Decision:
        t0 = time.perf_counter()
        timing = {"verify": None, "opa": None}
        info = {"request_id": uuid.uuid4().hex, "agent_did": None, "role": None,
                "action": action, "resource": None, "token_jti": None}

        async def finish(decision: str, status: int, reason: str):
            """Write the audit row, then either return (200) or raise the HTTP error."""
            total = _ms(t0)
            headers = {"X-Decision-Time-ms": f"{total:.3f}", "X-Request-ID": info["request_id"]}
            if timing["verify"] is not None:
                headers["X-Token-Verify-ms"] = f"{timing['verify']:.3f}"
            if timing["opa"] is not None:
                headers["X-OPA-ms"] = f"{timing['opa']:.3f}"
            try:
                await run_in_threadpool(
                    audit.write_audit, **info, decision=decision, reason=reason, http_status=status,
                    latency_ms=total, token_verify_ms=timing["verify"], opa_ms=timing["opa"])
            except Exception as e:  # noqa: BLE001
                if status == 200:  # cannot write the audit row -> do NOT run the action
                    raise HTTPException(503, "audit log unavailable - request denied", headers=headers)
                print(f"WARNING: audit write failed on a deny path: {e!r}")
            if status != 200:
                raise HTTPException(status, reason, headers=headers)
            for key, value in headers.items():
                response.headers[key] = value

        def decision_object() -> Decision:
            return Decision(request_id=info["request_id"], did=info["agent_did"], role=info["role"],
                            action=info["action"], resource=info["resource"], token_jti=info["token_jti"])

        # What is the target of this request? (may be invalid user input)
        resource_error = None
        try:
            info["resource"] = await resource_getter(request)
        except ValueError as e:
            resource_error = str(e)
            info["resource"] = "invalid-input"

        mode = settings.security_mode

        # ---- weak baselines (evaluation only) ----
        if mode in ("none", "header_only"):
            claimed_role = request.headers.get("x-agent-role")
            info["role"] = claimed_role
            if resource_error:
                await finish("DENY", 422, resource_error)
            if mode == "header_only":
                if action not in BASELINE_PERMISSIONS.get(claimed_role or "", set()):
                    await finish("DENY", 403, "header_only: role from header may not do this action")
                if info["resource"] in BASELINE_PROTECTED:
                    await finish("DENY", 403, "header_only: resource is protected")
            await finish("ALLOW", 200, f"SECURITY_MODE={mode}: baseline, no identity or capability checks")
            return decision_object()

        # ---- 1. Bearer token ----
        authorization = request.headers.get("authorization")
        if not authorization:
            await finish("DENY", 401, "missing bearer token")
        parts = authorization.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            await finish("DENY", 401, "malformed Authorization header (expected: Bearer <token>)")

        t1 = time.perf_counter()
        try:
            claims = tokens.verify_token(parts[1])
        except tokens.TokenError as e:
            timing["verify"] = _ms(t1)
            await finish("DENY", 401, str(e))
        except Exception:  # noqa: BLE001  anything unexpected = deny
            timing["verify"] = _ms(t1)
            await finish("DENY", 401, "token could not be verified")
        timing["verify"] = _ms(t1)
        info.update(agent_did=claims["sub"], role=claims["role"], token_jti=claims["jti"])

        if resource_error:
            await finish("DENY", 422, resource_error)

        # ---- 2. capability inside the token ----
        if not tokens.has_capability(claims["capabilities"], action, info["resource"]):
            await finish("DENY", 403, f"token has no capability for {action} on {info['resource']}")

        # ---- 3. OPA ----
        opa_input = {
            "did": claims["sub"], "role": claims["role"], "action": action,
            "resource": info["resource"], "capabilities": claims["capabilities"],
            "recent_action_count": rate_window.count(claims["sub"], action),
        }
        t2 = time.perf_counter()
        try:
            result = await run_in_threadpool(query_opa, opa_input)
        except OpaUnavailable as e:
            timing["opa"] = _ms(t2)
            await finish("ERROR", 503, f"policy engine unavailable ({e}) - denied (fail closed)")
        timing["opa"] = _ms(t2)

        if result.get("allow") is not True:  # only a real 'true' allows
            reasons = result.get("deny_reasons")
            text = "; ".join(str(r) for r in reasons) if isinstance(reasons, list) and reasons else "denied by policy"
            await finish("DENY", 403, text)

        rate_window.record(claims["sub"], action)
        await finish("ALLOW", 200, "allowed by policy")
        return decision_object()

    return dependency
