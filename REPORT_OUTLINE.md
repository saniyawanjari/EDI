# Report outline

Objectives used below:
1. Verifiable agent identity and short-lived, action-level capability tokens.
2. Single-point OPA enforcement that blocks unauthorised requests and logs every decision.
3. Measured authorization accuracy, decision latency and token-verification overhead in a simulated SOC.

## 1. Introduction
Autonomous security agents can act faster than humans, which is also why a wrong or hijacked action is costly. This chapter
introduces the problem, the idea of separating the power to suggest from the authority to execute, and the structure of the report.

## 2. Literature Review and Gaps
Review decentralized identifiers and Verifiable Credentials (W3C), capability-based security, policy engines such as
Open Policy Agent, zero-trust architectures and security for autonomous/AI agents. Identify the gap: few works combine
agent identity, per-action capabilities, central policy and tamper-evident auditing, and measure the cost.

## 3. Problem Statement and Objectives
State the problem (agents with broad standing permissions, spoofable roles, no accountable record) and list the three
objectives above as measurable goals.

## 4. System Design
Describe the architecture diagram in README.md: agents, identity layer (DID, DID Document, credential, challenge/response),
capability token, Supervisor enforcement point, OPA policy, simulated SOC tools, hash-chained audit log, dashboard.
Explain the threat model and the fail-closed rule. *(Objectives 1 and 2.)*

## 5. Implementation
Python/FastAPI, Ed25519 + EdDSA JWTs (cryptography, PyJWT), Rego policy with role table, capability matching, protected
resources and rate limit, SQLAlchemy audit log with SHA-256 chain, React/TypeScript dashboard, Docker packaging.
Mention what is simplified (no blockchain, simulated SOC, single node).

## 6. Testing and Evaluation
Unit and integration tests (`tests/`), then the 257-scenario evaluation (`eval/`): legitimate requests, ten attack
families, fail-closed cases, five runs, and two weak baselines (`header_only`, `none`) for comparison.
Define the metrics: accuracy, precision, recall, false-positive and false-negative rates, p50/p95/p99 latency.

## 7. Results and Discussion
Present `eval/output/results.md` and the charts. Objective 1: tampered, expired, forged, revoked and replayed credentials
or tokens are rejected. Objective 2: every attack scenario denied and every decision present in the audit log, with the
hash chain detecting edits. Objective 3: accuracy numbers and the latency/overhead of token verification and the OPA call.
Discuss any mistakes the evaluation reported, by scenario id.

## 8. Limitations and Future Work
Simulated SOC; DID/VC as concepts without a blockchain; single-node in-memory nonces and rate limits; unencrypted key
files; dashboard admin key in the browser; last-row truncation of the audit log. Future work: real DID methods and
status lists, hardware-backed keys, distributed rate limiting, external log anchoring, integration with a real SOAR.

## 9. Conclusion
Summarise how the three objectives were met and what the measurements show about security gained versus latency added.

## 10. References
W3C DID Core and Verifiable Credentials Data Model; RFC 7519 (JWT) and RFC 8032 (EdDSA); Open Policy Agent documentation;
NIST SP 800-207 (Zero Trust Architecture); further papers found in your literature search.

---
## Final submission checklist
- [ ] `pytest -v` passes (with OPA running, no test is skipped)
- [ ] `python eval/run_eval.py` ran; results pasted into README.md; mistakes (if any) explained
- [ ] No secrets committed: check `git status` for `.env`, `*.pem`, `agents/`, `data/`, `audit.db`
- [ ] README steps verified on a clean machine (clone, `make setup` or `.\run.ps1 setup`, run the demo)
- [ ] Screenshots taken: dashboard Overview, Live Audit with red DENY rows, Simulator, Agents, chain-broken message, evaluation charts
