# 5-minute demo script

Say the text in *italics*. Commands run from the project folder with the virtual environment active.

## 0. Before the demo (not counted)
`python scripts/create_agents.py` once, `.env` set, dashboard installed.

## 1. Start the system (30 s)
```
docker compose up -d opa          # terminal 1 (or: .\run.ps1 dev-api / make dev-api starts OPA and the API)
uvicorn main:app --port 8000      # terminal 2
cd dashboard && npm run dev       # terminal 3 -> open http://localhost:5173
```
*Three parts: the Supervisor in front of every action, OPA as the decision maker, and a dashboard that shows every decision.*

## 2. Normal flow A -> B -> C (60 s)
```
python scripts/agent_client.py log_analyst GET /api/v1/agent-a/report
python scripts/agent_client.py threat_detector GET /api/v1/agent-b/threats
python scripts/agent_client.py incident_responder POST /api/v1/agent-c/block ip=203.0.113.5
curl http://localhost:8000/api/v1/soc/blocked
```
*Each agent first proves its identity with its DID and credential, receives a 5-minute token for exactly its actions,
and the Supervisor asks OPA. A finds the IPs, B ranks them, only C can block. The IP now shows as blocked in the simulated SOC.*

(Or click **Simulator -> Normal flow** in the dashboard.)

## 3. The Log Analyst tries to block an IP: DENIED (45 s)
```
python scripts/agent_client.py log_analyst POST /api/v1/agent-c/block ip=198.51.100.77
```
*HTTP 403. The analyst may suggest, but its token has no `block_ip` capability. Open **Live Audit**: a red DENY row
appeared within two seconds, with the reason.*

## 4. Forged and expired tokens (60 s)
In the dashboard **Simulator**, click **Forged token**, then **Expired token** (or **Revoked token**).
*Both give 401. The forged token was signed with an attacker's key, the expired one is past its 5 minutes.
Each attempt is a red row in the audit log. Also try **Block the protected gateway IP**: 403, protected assets
override every allow rule.*

## 5. Audit log and hash chain (45 s)
In **Live Audit** click **Verify chain**: *Chain valid.* Then edit a row in the database:
```
sqlite3 audit.db "UPDATE audit_log SET reason='nothing happened' WHERE id=3;"
```
Click **Verify chain** again: *the chain is broken at row 3. Every row contains the hash of the previous one, so
nobody can silently change history.* (Restore with the original reason, or delete audit.db to start fresh.)

## 6. Evaluation results (60 s)
```
python eval/run_eval.py
```
*257 labelled requests, 5 runs. Show `eval/output/results.md` and the charts: accuracy, p95 decision latency,
and how many attacks succeed when only a role header is trusted or when there are no checks at all.*
