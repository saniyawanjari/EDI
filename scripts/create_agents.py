"""Create the three agents: keys, DIDs, DID Documents and credentials.

Run from the project root:   python scripts/create_agents.py

Results:
  agents/agent_a/  private_key.pem, credential.jwt, agent.json
  agents/agent_b/  ...
  agents/agent_c/  ...
  registry.json    (public DID Documents)
  issuer_key.pem   (created on first run)
Running it again creates NEW keys and NEW credentials (old ones stop working
because the DID Document now holds the new public key).
"""
import json
import os
import sys
from pathlib import Path

# Let this script import the "identity" package from the project root.
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from identity import registry  # noqa: E402
from identity.did import (  # noqa: E402
    build_did_document,
    generate_private_key,
    make_did,
    private_key_to_pem,
)
from identity.issuer import ensure_issuer_registered, issue_credential  # noqa: E402

AGENTS_DIR = Path(os.getenv("AGENTS_DIR", ROOT / "agents"))  # Docker sets AGENTS_DIR

# folder name, DID name, role, actions the credential lists
AGENTS = [
    ("agent_a", "agent-a", "log_analyst", ["read_logs"]),
    ("agent_b", "agent-b", "threat_detector", ["read_logs", "report_threat"]),
    ("agent_c", "agent-c", "incident_responder", ["block_ip", "isolate_host"]),
]


def ensure_gitignore() -> None:
    """Make sure secrets can never be committed by accident."""
    gitignore = ROOT / ".gitignore"
    lines = gitignore.read_text().splitlines() if gitignore.exists() else []
    additions = []
    if not any(line.strip() in ("agents/", "agents/*", "agents") for line in lines):
        additions.append("agents/")
    if "*.pem" not in [line.strip() for line in lines]:
        additions.append("*.pem")
    if additions:
        with open(gitignore, "a", encoding="utf-8") as f:
            f.write("\n".join(additions) + "\n")
        print(f"Added to .gitignore: {additions}")


def main() -> None:
    ensure_gitignore()
    ensure_issuer_registered()  # creates issuer_key.pem the first time

    for folder, did_name, role, actions in AGENTS:
        did = make_did(did_name)
        private_key = generate_private_key()

        # 1) publish the PUBLIC key in the registry (DID Document)
        registry.register_did(did, build_did_document(did, private_key.public_key()))

        # 2) the issuer signs a credential for this DID
        credential = issue_credential(did, role, actions, days_valid=30)

        # 3) save the agent's private files (git-ignored)
        agent_dir = AGENTS_DIR / folder
        agent_dir.mkdir(parents=True, exist_ok=True)
        key_path = agent_dir / "private_key.pem"
        key_path.write_bytes(private_key_to_pem(private_key))
        try:
            os.chmod(key_path, 0o600)
        except OSError:
            pass
        (agent_dir / "credential.jwt").write_text(credential)
        (agent_dir / "agent.json").write_text(
            json.dumps({"did": did, "role": role, "folder": folder}, indent=2)
        )
        print(f"Created {folder}: {did}  role={role}  actions={actions}")

        # 4) (Phase 5) also list the agent in the database table "agents"
        try:
            from audit import upsert_agent
            from db import init_db
            init_db()
            upsert_agent(did, role)
        except Exception as e:  # noqa: BLE001  the API also syncs agents at startup
            print(f"  (could not write agents table now: {e.__class__.__name__}; the API will sync it)")

    print("\nDone. Keys and credentials are in agents/ (git-ignored).")


if __name__ == "__main__":
    main()
