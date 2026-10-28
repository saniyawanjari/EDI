"""Agent C - Incident Responder. The only agent whose actions change the (simulated) SOC."""
import soc_tools


def execute_block(ip: str) -> dict:
    """Block one IP. The Supervisor calls this ONLY after identity, token and OPA all said yes."""
    return soc_tools.block_ip(ip)


def execute_isolate(host: str) -> dict:
    return soc_tools.isolate_host(host)


def block_threats(threats: list[dict]) -> list[dict]:
    """Block every medium/high threat directly (offline helper).

    NOTE: this skips the Supervisor, so the real flow does NOT use it. In the real flow
    the agent calls POST /api/v1/agent-c/block once per IP and each call is authorized.
    """
    actions = []
    for threat in threats:
        if threat["severity"] in ("medium", "high"):
            actions.append({"action": "block_ip", "target": threat["ip"],
                            "result": soc_tools.block_ip(threat["ip"])})
    return actions
