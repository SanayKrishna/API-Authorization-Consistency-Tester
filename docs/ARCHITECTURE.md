# Architecture & data flow

## Components

- `backend/app/main.py` — FastAPI UI API: health, policy validate, scan CRUD, reports, diff.
- `backend/app/schemas/policy.py` — Pydantic models: EndpointPolicy, IdentityConfig (with per-endpoint `resources` override), ScanRequest/Options, TestResult, Finding, ScanRecord.
- `backend/app/services/engine/` — reusable without frontend:
  - `testcase_gen.py` — deterministic matrix + expected allow/deny from policy only.
  - `executor.py` — httpx, per-request SSRF revalidation, max 2 same-origin redirects, timeout/connect handling.
  - `ownership.py` — body leak check + verdict state machine (404-on-allow → inconclusive).
  - `analyzers.py` — failure→finding mapping + policy-aware consistency grouping.
  - `severity.py` — rule table (Critical/High/Medium/Low/Info + confirmed/suspicious).
  - `scanner.py` — orchestrator with semaphore + rate delay + progress callback.
  - `reporter.py` — JSON/CSV/HTML, redacted.
- `backend/app/security/` — `target_validator.py` (allowlist, DNS/IP, rebinding guard), `redaction.py`.
- `backend/app/store/file_store.py` — memory + `reports/scans/*.json`.
- `demo_api/app/main.py` — synthetic users/orders, JWT (PyJWT), secure endpoints + V1/V2/V3 vulns.
- `frontend/src/` — React+TS+Vite+Tailwind, hash-free BrowserRouter, real fetch only.

## Request lifecycle

1. UI POSTs ScanRequest (tokens in memory only; echoed config redacted).
2. Backend validates base URL, stores `running` ScanRecord, background `run_scan`.
3. `expand_cases` → `asyncio.gather` bounded → each `execute_one` revalidates URL.
4. Verdict + leak → findings → consistency pass → summary → store + JSON file.
5. UI polls `GET /scans/{id}` (real progress), downloads reports, `GET /diff` for regression.
