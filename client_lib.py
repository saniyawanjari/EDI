"""Agent-side helper functions (used by scripts/agent_client.py, demo.py and eval/).

An agent proves who it is (challenge -> sign -> verify), gets a capability token,
and then calls the Supervisor with 'Authorization: Bearer <token>'.
SIMPLIFIED: real agents would be separate programs; here we reuse our own helpers.
"""
import json
import os
from pathlib import Path

import httpx

from identity.did import b64url_encode, load_private_key_from_pem, sign_message

PROJECT_ROOT = Path(__file__).resolve().parent
AGENTS_DIR = Path(os.getenv("AGENTS_DIR", PROJECT_ROOT / "agents"))


def load_agent(name_or_role: str) -> dict:
    """Find an agent by folder name (agent_a) or role (log_analyst)."""
    for info_file in AGENTS_DIR.glob("*/agent.json"):
        info = json.loads(info_file.read_text())
        if name_or_role in (info["folder"], info["role"]):
            folder = info_file.parent
            return {
                "did": info["did"],
                "role": info["role"],
                "private_key": load_private_key_from_pem((folder / "private_key.pem").read_bytes()),
                "vc_jwt": (folder / "credential.jwt").read_text().strip(),
            }
    raise SystemExit(f"Agent '{name_or_role}' not found in {AGENTS_DIR}. Run: python scripts/create_agents.py")


def request_token(agent: dict, base_url: str, capabilities: list[dict] | None = None,
                  vc_jwt: str | None = None, signing_key=None,
                  client: httpx.Client | None = None) -> httpx.Response:
    """challenge -> sign -> POST /token. Returns the raw /token response.
    vc_jwt and signing_key can be replaced to simulate attacks (tampered credential, wrong key)."""
    http = client or httpx
    r = http.post(f"{base_url}/api/v1/auth/challenge", json={"did": agent["did"]}, timeout=5)
    r.raise_for_status()
    nonce = r.json()["nonce"]
    signature = b64url_encode(sign_message(signing_key or agent["private_key"], nonce.encode("utf-8")))
    body = {"did": agent["did"], "signature": signature, "vc_jwt": vc_jwt or agent["vc_jwt"]}
    if capabilities is not None:
        body["capabilities"] = capabilities
    return http.post(f"{base_url}/api/v1/token", json=body, timeout=5)


def get_token(agent: dict, base_url: str, **kwargs) -> str:
    r = request_token(agent, base_url, **kwargs)
    if r.status_code != 200:
        raise RuntimeError(f"token request failed: HTTP {r.status_code} {r.text}")
    return r.json()["access_token"]


def local_identity(agent: dict) -> dict:
    """Run the identity proof IN THIS PROCESS (no HTTP). Needs the project's key files.
    Used only to build special test tokens (e.g. expired) with the Supervisor key."""
    from identity.auth import authenticate_agent, create_challenge

    nonce = create_challenge(agent["did"])
    signature = b64url_encode(sign_message(agent["private_key"], nonce.encode("utf-8")))
    return authenticate_agent(agent["did"], signature, agent["vc_jwt"])


def call(base_url: str, method: str, path: str, token: str | None = None,
         json_body: dict | None = None, headers: dict | None = None,
         client: httpx.Client | None = None) -> httpx.Response:
    all_headers = dict(headers or {})
    if token:
        all_headers["Authorization"] = f"Bearer {token}"
    return (client or httpx).request(method, f"{base_url}{path}", json=json_body,
                                     headers=all_headers, timeout=10)
