# Linux/macOS shortcuts. Windows users: use  .\run.ps1 <action>
PY := .venv/bin/python

.PHONY: setup opa start dev-api dev-ui test evaluate stop

setup:            ## create venv, install packages, make .env, create agents, install dashboard packages
	python3 -m venv .venv
	$(PY) -m pip install -r requirements.txt
	test -f .env || cp .env.example .env
	test -f dashboard/.env || cp dashboard/.env.example dashboard/.env
	$(PY) scripts/create_agents.py
	cd dashboard && npm install
	@echo "Now edit .env and dashboard/.env: set the SAME ADMIN_KEY in both."

opa:              ## start only OPA in Docker
	docker compose up -d opa

start:            ## start EVERYTHING in Docker (opa, db, api, dashboard)
	docker compose up --build -d
	docker compose exec api python scripts/create_agents.py
	@echo "Dashboard: http://localhost:5173   API docs: http://localhost:8000/docs"

dev-api: opa      ## run the API locally with auto-reload
	$(PY) -m uvicorn main:app --reload --port 8000

dev-ui:           ## run the dashboard locally
	cd dashboard && npm run dev

test:             ## run all tests (start OPA first for the full set)
	$(PY) -m pytest -v

evaluate:         ## run the Phase 7 evaluation (needs OPA, ADMIN_KEY and agents)
	$(PY) eval/run_eval.py

stop:             ## stop all Docker containers
	docker compose down
