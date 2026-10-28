# Windows PowerShell shortcuts.   Usage:  .\run.ps1 <action>
# Actions: setup | opa | start | dev-api | dev-ui | test | evaluate | stop
param([string]$Action = "help")

$py = ".\.venv\Scripts\python.exe"

switch ($Action) {
    "setup" {
        python -m venv .venv
        & $py -m pip install -r requirements.txt
        if (-not (Test-Path .env)) { Copy-Item .env.example .env }
        if (-not (Test-Path dashboard\.env)) { Copy-Item dashboard\.env.example dashboard\.env }
        & $py scripts\create_agents.py
        Push-Location dashboard; npm install; Pop-Location
        Write-Host "Now edit .env and dashboard\.env: set the SAME ADMIN_KEY in both."
    }
    "opa"      { docker compose up -d opa }
    "start"    {
        docker compose up --build -d
        docker compose exec api python scripts/create_agents.py
        Write-Host "Dashboard: http://localhost:5173   API docs: http://localhost:8000/docs"
    }
    "dev-api"  { docker compose up -d opa; & $py -m uvicorn main:app --reload --port 8000 }
    "dev-ui"   { Push-Location dashboard; npm run dev; Pop-Location }
    "test"     { & $py -m pytest -v }
    "evaluate" { & $py eval\run_eval.py }
    "stop"     { docker compose down }
    default    { Write-Host "Usage: .\run.ps1 setup | opa | start | dev-api | dev-ui | test | evaluate | stop" }
}
