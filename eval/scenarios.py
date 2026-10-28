"""Labelled test requests for the evaluation (Phase 7).

Each Scenario is ONE request we send to the Supervisor, with the answer we EXPECT:
  expected = "ALLOW"  -> a legitimate request
  expected = "DENY"   -> an attack (or a fail-closed case)
credential_state tells the runner HOW the caller presents (or fakes) its credentials:
  valid          real token with all rights of the credential
  narrow_token   real token limited to the capabilities in 'scope'
  none           no token at all
  forged_token   token signed with the attacker's own key
  expired_token  correctly signed token that is already expired
  revoked_token  correctly signed token that the admin revoked
  replayed_token token used once, revoked, then replayed
  tampered_vc    credential edited (role changed) before asking for a token
  wrong_key      nonce signed with a key that is not the agent's
'header_role' is the x-agent-role header. The real system ignores it; the weak baseline
modes trust it (that is how "role spoofing" works there).
"""
from dataclasses import dataclass

A, B, C = "log_analyst", "threat_detector", "incident_responder"
READ_LOGS = "/api/v1/agent-a/report"
THREATS = "/api/v1/agent-b/threats"
BLOCK = "/api/v1/agent-c/block"
ISOLATE = "/api/v1/agent-c/isolate"


@dataclass
class Scenario:
    id: str
    name: str
    type: str
    agent: str
    method: str
    endpoint: str
    payload: dict | None
    credential_state: str
    expected: str
    header_role: str
    prelude: int = 0          # how many allowed blocks to do first (rate-limit scenarios)
    server: str = "full"      # "opa_down" = run against a Supervisor whose OPA is unreachable
    scope: list | None = None  # capabilities for narrow_token

    @property
    def is_attack(self) -> bool:
        return self.expected == "DENY"


def ip(i: int) -> str:
    return f"10.20.{i // 250}.{i % 250 + 1}"


def host(i: int) -> str:
    return f"web-{i:02d}"


def build_scenarios() -> list[Scenario]:
    out: list[Scenario] = []

    def add(name, type_, agent, method, endpoint, payload, state, expected, header_role, **kw):
        out.append(Scenario(f"S{len(out) + 1:03d}", name, type_, agent, method, endpoint,
                            payload, state, expected, header_role, **kw))

    # ------------------------------------------------ LEGITIMATE (110) -> ALLOW
    for _ in range(20):
        add("Agent A reads logs", "legit_read_logs", A, "GET", READ_LOGS, None, "valid", "ALLOW", A)
    for _ in range(20):
        add("Agent B reports threats", "legit_report_threat", B, "GET", THREATS, None, "valid", "ALLOW", B)
    for i in range(40):
        add(f"Agent C blocks {ip(i)}", "legit_block_ip", C, "POST", BLOCK, {"ip": ip(i)}, "valid", "ALLOW", C)
    for i in range(30):
        add(f"Agent C isolates {host(i)}", "legit_isolate_host", C, "POST", ISOLATE,
            {"host": host(i)}, "valid", "ALLOW", C)

    # ------------------------------------------------ ATTACKS (147) -> DENY
    # Wrong role for the action (valid identity, but no authority).
    for k in range(10):
        add("Log Analyst blocks an IP", "atk_role_violation", A, "POST", BLOCK, {"ip": ip(100 + k)}, "valid", "DENY", A)
    for k in range(10):
        add("Threat Detector isolates a host", "atk_role_violation", B, "POST", ISOLATE,
            {"host": host(50 + k)}, "valid", "DENY", B)
    for k in range(5):
        add("Log Analyst isolates a host", "atk_role_violation", A, "POST", ISOLATE,
            {"host": host(60 + k)}, "valid", "DENY", A)
    for _ in range(5):
        add("Incident Responder reads logs", "atk_role_violation", C, "GET", READ_LOGS, None, "valid", "DENY", C)
    for k in range(5):
        add("Threat Detector blocks an IP", "atk_role_violation", B, "POST", BLOCK, {"ip": ip(110 + k)}, "valid", "DENY", B)

    # Right action, wrong resource: token only covers ONE resource.
    for k in range(5):
        add("Token for one IP used on another IP", "atk_wrong_resource", C, "POST", BLOCK, {"ip": ip(300 + k)},
            "narrow_token", "DENY", C, scope=[{"action": "block_ip", "resource": f"ip:{ip(200 + k)}"}])
    for k in range(5):
        add("Token for one host used on another host", "atk_wrong_resource", C, "POST", ISOLATE,
            {"host": host(91 + k)}, "narrow_token", "DENY", C,
            scope=[{"action": "isolate_host", "resource": "host:web-90"}])

    # Protected assets (also tries tricky spellings).
    for k, value in enumerate(["192.168.1.1", " 192.168.1.1 ", "::ffff:192.168.1.1", "192.168.1.1"] * 2):
        add(f"Block protected IP ({value!r})", "atk_protected", C, "POST", BLOCK, {"ip": value}, "valid", "DENY", C)
    for k, value in enumerate(["db-01", "DB-01", "Db-01", "db-01"] * 2):
        add(f"Isolate protected host ({value!r})", "atk_protected", C, "POST", ISOLATE,
            {"host": value}, "valid", "DENY", C)

    # Bad credentials. Each of these tries one of four targets in turn.
    targets = [
        (A, "GET", READ_LOGS, lambda i: None),
        (B, "GET", THREATS, lambda i: None),
        (C, "POST", BLOCK, lambda i: {"ip": ip(500 + i)}),
        (C, "POST", ISOLATE, lambda i: {"host": host(70 + i % 25)}),
    ]
    for state, count, type_, label in [
        ("expired_token", 10, "atk_expired_token", "Expired token"),
        ("forged_token", 10, "atk_forged_token", "Forged token"),
        ("revoked_token", 10, "atk_revoked_token", "Revoked token"),
        ("replayed_token", 5, "atk_replayed_token", "Replayed token after revocation"),
        ("none", 10, "atk_missing_token", "No token"),
        ("tampered_vc", 10, "atk_tampered_credential", "Tampered credential"),
        ("wrong_key", 5, "atk_wrong_key", "Signature with the wrong key"),
    ]:
        for k in range(count):
            agent, method, endpoint, payload_fn = targets[k % 4]
            add(label, type_, agent, method, endpoint, payload_fn(k), state, "DENY", agent)

    # Role spoofing through the old header: a log analyst token + "I am the responder".
    for k in range(5):
        add("Spoofed x-agent-role (analyst token)", "atk_header_spoofing", A, "POST", BLOCK,
            {"ip": ip(600 + k)}, "valid", "DENY", C)
    for k in range(5):
        add("Spoofed x-agent-role (detector token)", "atk_header_spoofing", B, "POST", ISOLATE,
            {"host": host(80 + k)}, "valid", "DENY", C)

    # More than 5 blocks in one minute: 5 allowed first, the 6th must be denied.
    for k in range(6):
        add("6th block within a minute", "atk_rate_limit", C, "POST", BLOCK, {"ip": ip(700 + k)},
            "valid", "DENY", C, prelude=5)

    # ------------------------------------------------ FAIL-CLOSED (10) -> DENY (503)
    for name, agent, method, endpoint, payload in [
        ("A reads logs while OPA is down", A, "GET", READ_LOGS, None),
        ("A reads logs while OPA is down", A, "GET", READ_LOGS, None),
        ("A reads logs while OPA is down", A, "GET", READ_LOGS, None),
        ("B reports threats while OPA is down", B, "GET", THREATS, None),
        ("B reports threats while OPA is down", B, "GET", THREATS, None),
        ("C blocks an IP while OPA is down", C, "POST", BLOCK, {"ip": ip(800)}),
        ("C blocks an IP while OPA is down", C, "POST", BLOCK, {"ip": ip(801)}),
        ("C blocks an IP while OPA is down", C, "POST", BLOCK, {"ip": ip(802)}),
        ("C isolates a host while OPA is down", C, "POST", ISOLATE, {"host": host(10)}),
        ("C isolates a host while OPA is down", C, "POST", ISOLATE, {"host": host(11)}),
    ]:
        add(name, "failclosed_opa_down", agent, method, endpoint, payload, "valid", "DENY", agent, server="opa_down")

    return out


if __name__ == "__main__":
    scenarios = build_scenarios()
    legit = sum(1 for s in scenarios if not s.is_attack)
    print(f"{len(scenarios)} scenarios: {legit} legitimate, {len(scenarios) - legit} attack/fail-closed")
