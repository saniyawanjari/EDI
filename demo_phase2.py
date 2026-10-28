"""Phase 2 demo: try every role against every endpoint and print an ALLOWED/DENIED table.

This uses the OLD x-agent-role header, which only the weak baseline mode understands.
Start the API like this first:
    PowerShell:  $env:SECURITY_MODE="header_only"; uvicorn main:app --port 8000
    Linux/macOS: SECURITY_MODE=header_only uvicorn main:app --port 8000
(OPA is not needed in this mode.)
"""
import os

import httpx

BASE = os.getenv("SUPERVISOR_URL", "http://localhost:8000")
ROLES = ["log_analyst", "threat_detector", "incident_responder", "intruder"]
ENDPOINTS = [
    ("GET", "/api/v1/agent-a/report", None),
    ("GET", "/api/v1/agent-b/threats", None),
    ("POST", "/api/v1/agent-c/block", {"ip": "203.0.113.50"}),
    ("POST", "/api/v1/agent-c/block", {"ip": "192.168.1.1"}),
    ("POST", "/api/v1/agent-c/isolate", {"host": "web-01"}),
    ("POST", "/api/v1/agent-c/isolate", {"host": "db-01"}),
]


def label(method, path, body):
    return f"{method} {path.split('/api/v1/')[1]} {list(body.values())[0] if body else ''}".strip()


def main():
    print(f"{'endpoint':<40}" + "".join(f"{r:<22}" for r in ROLES))
    for method, path, body in ENDPOINTS:
        row = f"{label(method, path, body):<40}"
        for role in ROLES:
            r = httpx.request(method, BASE + path, json=body, headers={"x-agent-role": role}, timeout=5)
            row += f"{('ALLOWED' if r.status_code == 200 else 'DENIED') + ' ' + str(r.status_code):<22}"
        print(row)


if __name__ == "__main__":
    main()
