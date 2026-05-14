# GhostTrace

## AI-Powered Malware & Threat Investigation Platform

GhostTrace is a defensive cybersecurity platform for analyzing suspicious files, URLs, and logs, extracting IOCs, and generating forensic PDF reports.

## Current Project Structure

- `backend/` - FastAPI API, analysis services, report generation, persistence helpers
- `frontend/` - React + Vite frontend UI with active backend integration
- `docker-compose.yml` - Local multi-service orchestration
- `docs/` - Process and policy documentation
- `.github/workflows/` - CI quality checks

## Backend Quick Start

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Frontend Quick Start

```powershell
cd frontend
npm install
npm run dev
```

## Environment Notes

- Backend configuration comes from `backend/.env`
- Do not commit real secrets
- Use `backend/.env.example` as the template

## Core API Endpoints

- `GET /health`
- `POST /api/analyze-file`
- `POST /api/generate-report`
- `POST /api/analyze-url`
- `POST /api/generate-url-report`
- `POST /api/analyze-log`
- `POST /api/generate-log-report`
- `GET /api/history/files`
- `GET /api/history/urls`
- `GET /api/history/logs`
- `GET /api/reports`
- `POST /api/settings/api-keys`
- `GET /api/settings/api-keys` (masked response)
- `GET /api/security-libs-status`
- `GET /api/monitor/status`

## Current Frontend Coverage

- Connected to backend: file/url/log scans, report generation, history/reports listing, settings save/load, and backend health/status polling.
- Status UI is auth-aware:
  - `Connected`
  - `Missing API key`
  - `Invalid API key`
  - `Backend down`

## Repo Hygiene Notes

- Runtime/build directories such as `frontend/node_modules`, `frontend/dist`, `backend/.venv`, and `backend/.pytest_cache` are intentionally ignored via `.gitignore`.
- If these were previously committed, remove them from git tracking history/state to keep the repository clean.
