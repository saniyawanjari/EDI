"""Agent client: get a capability token, then call any endpoint (Phase 3 + 4).

Run from the project root, with the API running on port 8000:

  python scripts/agent_client.py log_analyst GET /api/v1/agent-a/report
  python scripts/agent_client.py incident_responder POST /api/v1/agent-c/block ip=203.0.113.5
  python scripts/agent_client.py incident_responder POST /api/v1/agent-c/isolate host=web-01
  python scripts/agent_client.py agent_a            # only the Phase 3 identity proof

Roles: log_analyst, threat_detector, incident_responder (or agent_a / agent_b / agent_c).
Body fields are written as key=value (easy in PowerShell too), or one JSON object.
"""
import json
import os
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import client_lib  # noqa: E402

BASE_URL = os.getenv("SUPERVISOR_URL", "http://localhost:8000")


def parse_body(parts: list[str]) -> dict | None:
    if not parts:
        return None
    if len(parts) == 1 and parts[0].lstrip().startswith("{"):
        return json.loads(parts[0])
    return dict(item.split("=", 1) for item in parts)


def identity_proof_only(agent_name: str) -> None:
    """Phase 3 behaviour: challenge -> sign -> /auth/verify."""
    from identity.did import b64url_encode, sign_message

    agent = client_lib.load_agent(agent_name)
    nonce = httpx.post(f"{BASE_URL}/api/v1/auth/challenge", json={"did": agent["did"]}, timeout=5).json()["nonce"]
    signature = b64url_encode(sign_message(agent["private_key"], nonce.encode()))
    r = httpx.post(f"{BASE_URL}/api/v1/auth/verify",
                   json={"did": agent["did"], "signature": signature, "vc_jwt": agent["vc_jwt"]}, timeout=5)
    print(f"HTTP {r.status_code}")
    print(json.dumps(r.json(), indent=2))


def main() -> None:
    args = sys.argv[1:]
    if len(args) == 1:
        return identity_proof_only(args[0])
    if len(args) < 3:
        raise SystemExit(__doc__)
    agent_name, method, path, *body_parts = args
    agent = client_lib.load_agent(agent_name)

    token_response = client_lib.request_token(agent, BASE_URL)
    if token_response.status_code != 200:
        print(f"Could not get a token: HTTP {token_response.status_code} {token_response.text}")
        raise SystemExit(1)
    token = token_response.json()["access_token"]
    print(f"Got a token for {agent['did']} (valid {token_response.json()['expires_in']} s)")

    r = client_lib.call(BASE_URL, method.upper(), path, token=token, json_body=parse_body(body_parts))
    print(f"HTTP {r.status_code}   decision time: {r.headers.get('X-Decision-Time-ms', '-')} ms")
    try:
        print(json.dumps(r.json(), indent=2))
    except ValueError:
        print(r.text)


if __name__ == "__main__":
    try:
        main()
    except httpx.HTTPError as e:
        raise SystemExit(f"Could not reach the Supervisor at {BASE_URL}: {e}")
