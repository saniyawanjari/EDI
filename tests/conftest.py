"""Shared test setup. The environment is prepared BEFORE the app is imported, so the tests
use temporary files and a temporary database and never touch your real keys or audit.db."""
import os
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="soc_tests_"))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test_audit.db').as_posix()}"
os.environ["ADMIN_KEY"] = "test-admin-key"
os.environ["SECURITY_MODE"] = "full"
os.environ["REGISTRY_PATH"] = str(_TMP / "registry.json")
os.environ["ISSUER_KEY_PATH"] = str(_TMP / "issuer_key.pem")
os.environ["SERVER_KEY_PATH"] = str(_TMP / "server_key.pem")
os.environ["AGENTS_DIR"] = str(_TMP / "agents")


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    import main

    with TestClient(main.app) as test_client:  # runs startup: creates the tables
        yield test_client


@pytest.fixture(scope="session")
def agents():
    """The three agents (DID, private key, credential), registered in the temporary registry."""
    from identity import issuer, registry
    from identity.did import build_did_document, generate_private_key

    result = {}
    for name, role, actions in [
        ("agent-a", "log_analyst", ["read_logs"]),
        ("agent-b", "threat_detector", ["read_logs", "report_threat"]),
        ("agent-c", "incident_responder", ["block_ip", "isolate_host"]),
    ]:
        did = f"did:example:{name}"
        key = generate_private_key()
        registry.register_did(did, build_did_document(did, key.public_key()))
        result[role] = {"did": did, "key": key, "vc": issuer.issue_credential(did, role, actions)}
    return result


@pytest.fixture(autouse=True)
def clean_state():
    """Every test starts with an empty rate-limit window and an empty simulated SOC."""
    import enforcement
    import soc_tools

    enforcement.rate_window.reset()
    soc_tools.reset()
    yield
