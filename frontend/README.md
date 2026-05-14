# GhostTrace Frontend

React + Vite frontend for GhostTrace.

## Available Scripts

- `npm run dev` - start development server
- `npm run build` - production build
- `npm run preview` - preview production build
- `npm run test` - run frontend tests

## Backend Integration

Frontend consumes backend endpoints under `http://localhost:8000/api` by default.

Optional environment variables:

- `VITE_GHOSTTRACE_API_BASE` (default: `http://localhost:8000`)
- `VITE_GHOSTTRACE_API_KEY` (sent as `x-api-key`)

Current integration status:

- Connected: file/url/log scan actions, PDF report actions, history/reports listing, and settings save/load API-key flow
- Health/status polling: `/health`, `/api/security-libs-status`, `/api/monitor/status`
- Auth-aware status labels: Connected, Missing API key, Invalid API key, Backend down

## Entry Files

- `src/main.jsx`
- `src/GhostTrace.jsx`
