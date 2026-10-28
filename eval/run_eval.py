"""Run the full evaluation (Phase 7).   python eval/run_eval.py

What it does:
  1. Starts its OWN Supervisor servers (separate ports, separate throw-away databases):
       full        SECURITY_MODE=full          the real system
       header_only SECURITY_MODE=header_only   weak baseline: trusts the x-agent-role header
       none        SECURITY_MODE=none          baseline: no checks at all
       opa_down    full mode, but OPA URL points to a dead port (tests "fail closed")
     The baselines exist ONLY to show how much protection the real system adds.
  2. 10 warm-up requests, then every scenario, 5 runs.
  3. Computes accuracy, precision, recall, error rates, confusion matrix, latency percentiles.
  4. Writes eval/output/: results.csv, summary.json, results.md and four PNG charts.

Before you start:  OPA must be running (docker or binary), ADMIN_KEY must be set in .env,
and `python scripts/create_agents.py` must have been run.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx
import jwt as pyjwt
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import client_lib  # noqa: E402
import report  # noqa: E402
import tokens  # noqa: E402
from config import settings  # noqa: E402
from identity.did import b64url_decode, b64url_encode, generate_private_key  # noqa: E402
from scenarios import A, B, C, build_scenarios  # noqa: E402

OUT = ROOT / "eval" / "output"
RUNS = 5
WARMUP = 10
SERVERS = {  # name: (port, extra environment)
    "full": (8101, {"SECURITY_MODE": "full"}),
    "header_only": (8102, {"SECURITY_MODE": "header_only"}),
    "none": (8103, {"SECURITY_MODE": "none"}),
    "opa_down": (8104, {"SECURITY_MODE": "full", "OPA_URL": "http://127.0.0.1:9/v1/data/authz/allow"}),
}
BASELINES = ("header_only", "none")


# ------------------------------------------------------------------ servers
class Server:
    def __init__(self, name: str, port: int, extra_env: dict):
        self.name, self.port, self.extra_env = name, port, extra_env
        self.base = f"http://127.0.0.1:{port}"
        self.process = None

    def start(self) -> None:
        OUT.mkdir(parents=True, exist_ok=True)
        db_file = OUT / f"eval_{self.name}.db"
        db_file.unlink(missing_ok=True)  # every evaluation starts with an empty audit log
        env = {**os.environ, **self.extra_env, "ADMIN_KEY": settings.admin_key,
               "DATABASE_URL": f"sqlite:///{db_file.as_posix()}"}
        log = open(OUT / f"server_{self.name}.log", "w")
        self.process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "main:app", "--port", str(self.port), "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        for _ in range(60):
            if self.process.poll() is not None:
                raise SystemExit(f"Server '{self.name}' stopped at startup. See eval/output/server_{self.name}.log")
            try:
                if httpx.get(f"{self.base}/health", timeout=1).status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.5)
        raise SystemExit(f"Server '{self.name}' did not start in 30 s. See eval/output/server_{self.name}.log")

    def stop(self) -> None:
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


# ------------------------------------------------------------------ attack helpers
def tamper_credential(vc_jwt: str) -> str:
    """Change the role inside the credential but keep the old signature."""
    import json
    header, payload, signature = vc_jwt.split(".")
    claims = json.loads(b64url_decode(payload))
    claims["vc"]["credentialSubject"]["role"] = "incident_responder"
    claims["vc"]["credentialSubject"]["allowed_actions"] = ["block_ip", "isolate_host"]
    return f"{header}.{b64url_encode(json.dumps(claims).encode())}.{signature}"


def forge_token(agent: dict) -> str:
    """A token with every capability, signed by the ATTACKER's own key."""
    now = datetime.now(timezone.utc)
    caps = tokens.capabilities_from_actions(list(tokens.ACTION_RESOURCE))
    claims = {"iss": tokens.ISSUER, "aud": tokens.AUDIENCE, "sub": agent["did"], "role": agent["role"],
              "capabilities": caps, "jti": "forged", "iat": now, "exp": now + timedelta(minutes=5)}
    return pyjwt.encode(claims, generate_private_key(), algorithm="EdDSA")


def ms_header(response: httpx.Response, name: str):
    value = response.headers.get(name)
    return float(value) if value is not None else None


# ------------------------------------------------------------------ one scenario
def run_scenario(sc, server: Server, run_no: int, http: httpx.Client, agents: dict, admin: dict) -> dict:
    base = server.base
    http.post(f"{base}/api/v1/admin/reset-state", headers=admin)  # rate limit + SOC start fresh
    agent = agents[sc.agent]
    baseline = server.name in BASELINES
    headers = {"x-agent-role": sc.header_role}  # the real system ignores this header
    row = {"scenario_id": sc.id, "name": sc.name, "type": sc.type, "mode": server.name, "run": run_no,
           "expected": sc.expected, "decision": None, "status": None, "correct": None,
           "request_ms": None, "decision_ms": None, "token_verify_ms": None, "opa_ms": None, "detail": ""}

    def finish(status: int, response=None, detail: str = "", timed=None):
        row["status"] = status
        row["decision"] = "ALLOW" if status == 200 else "DENY"
        row["correct"] = row["decision"] == sc.expected
        row["detail"] = detail[:120]
        if response is not None:
            row["decision_ms"] = ms_header(response, "X-Decision-Time-ms")
            row["token_verify_ms"] = ms_header(response, "X-Token-Verify-ms")
            row["opa_ms"] = ms_header(response, "X-OPA-ms")
        row["request_ms"] = timed
        return row

    # ---- get (or fake) the credentials ----
    token = None
    if not baseline and sc.credential_state != "none":
        state = sc.credential_state
        if state in ("valid", "narrow_token", "revoked_token", "replayed_token"):
            r = client_lib.request_token(agent, base, capabilities=sc.scope, client=http)
            if r.status_code != 200:
                return finish(r.status_code, r, f"token request refused: {r.text}")
            token = r.json()["access_token"]
            if state in ("revoked_token", "replayed_token"):
                if state == "replayed_token":  # the thief uses the token once while it is still valid
                    client_lib.call(base, sc.method, sc.endpoint, token, sc.payload, headers, http)
                jti = pyjwt.decode(token, options={"verify_signature": False})["jti"]
                http.post(f"{base}/api/v1/admin/revoke", json={"jti": jti}, headers=admin)
        elif state in ("tampered_vc", "wrong_key"):
            kwargs = ({"vc_jwt": tamper_credential(agent["vc_jwt"])} if state == "tampered_vc"
                      else {"signing_key": generate_private_key()})
            r = client_lib.request_token(agent, base, client=http, **kwargs)
            if r.status_code != 200:  # the attack already failed at the identity step
                return finish(r.status_code, r, f"identity step refused: {r.text}")
            token = r.json()["access_token"]  # attack got through the identity step (a mistake)
        elif state == "forged_token":
            token = forge_token(agent)
        elif state == "expired_token":
            token = tokens.issue_token(client_lib.local_identity(agent), ttl_seconds=-60)

    # ---- rate-limit scenarios: 5 allowed blocks first (not scored) ----
    for i in range(sc.prelude):
        client_lib.call(base, "POST", "/api/v1/agent-c/block", token, {"ip": f"10.99.0.{i + 1}"}, headers, http)

    # ---- the scored request ----
    start = time.perf_counter()
    r = client_lib.call(base, sc.method, sc.endpoint, token, sc.payload, headers, http)
    elapsed = (time.perf_counter() - start) * 1000
    detail = r.json().get("detail", "") if r.status_code != 200 and r.headers.get("content-type", "").startswith("application/json") else ""
    return finish(r.status_code, r, str(detail), elapsed)


# ------------------------------------------------------------------ main
def opa_reachable() -> bool:
    try:
        return httpx.post(settings.opa_url, json={"input": {}}, timeout=2).status_code == 200
    except httpx.HTTPError:
        return False


def main() -> None:
    if not settings.admin_key:
        raise SystemExit("ADMIN_KEY is empty. Copy .env.example to .env and set ADMIN_KEY.")
    if not opa_reachable():
        raise SystemExit(f"OPA is not reachable at {settings.opa_url}. Start it first (see README).")
    agents = {role: client_lib.load_agent(role) for role in (A, B, C)}
    scenarios = build_scenarios()
    admin = {"x-admin-key": settings.admin_key}
    rows: list[dict] = []

    servers = {name: Server(name, port, env) for name, (port, env) in SERVERS.items()}
    try:
        for server in servers.values():
            print(f"Starting server '{server.name}' on port {server.port} ...")
            server.start()

        for name, server in servers.items():
            wanted = [s for s in scenarios if (s.server == "opa_down") == (name == "opa_down")]
            with httpx.Client(timeout=10) as http:
                if name != "opa_down":  # 10 warm-up requests (not recorded)
                    warm = wanted[0]
                    for _ in range(WARMUP):
                        run_scenario(warm, server, 0, http, agents, admin)
                for run_no in range(1, RUNS + 1):
                    for sc in wanted:
                        rows.append(run_scenario(sc, server, run_no, http, agents, admin))
                    print(f"  {name}: run {run_no}/{RUNS} done ({len(wanted)} scenarios)")
    finally:
        for server in servers.values():
            server.stop()

    summary = report.summarize(rows)
    report.write_all(rows, summary, OUT)

    fs = summary["full_system"]
    print("\n=== RESULT (full system) ===")
    print(f"accuracy {fs['accuracy']}  precision {fs['precision']}  recall {fs['recall']}")
    print(f"false-positive rate {fs['false_positive_rate']}  false-negative rate {fs['false_negative_rate']}")
    print(f"confusion matrix [[TP, FN], [FP, TN]] = {fs['confusion_matrix']['values']}")
    for mode, m in summary["modes"].items():
        print(f"{mode:12s}: {m['attacks_succeeded']} of {m['attack_requests']} attack requests succeeded")
    if summary["mistakes"]:
        print("\nMISTAKES (scenario id, type, expected, got):")
        for m in summary["mistakes"]:
            print(f"  {m['scenario_id']}  {m['type']}  expected {m['expected']}  got HTTP {m['got_status']}  x{m['times']}")
    else:
        print("\nNo mistakes: every attack denied, every legitimate request allowed.")
    print(f"\nFiles written to {OUT}")


if __name__ == "__main__":
    main()
