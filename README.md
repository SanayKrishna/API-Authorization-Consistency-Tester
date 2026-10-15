# API Authorization Consistency Tester

Deterministic, policy-driven security testing for REST API authorization — covering role enforcement, authentication states, object-level ownership (BOLA/IDOR), and cross-endpoint consistency.

Built with **Python 3.11+ / FastAPI / httpx / Pydantic / pytest** on the backend and **React + TypeScript + Vite + Tailwind CSS** on the frontend. Ships with an isolated local demo API containing secure endpoints and three documented intentional vulnerabilities, so every detection claim is reproducible.

> No mocked scans. Every number in the UI comes from the live testing engine. No ML, no cloud services, no containers required.

---

## Table of contents

- [Why this exists](#why-this-exists)
- [Key capabilities](#key-capabilities)
- [Repository layout](#repository-layout)
- [Quickstart](#quickstart)
- [Configuring a scan](#configuring-a-scan)
- [Understanding results](#understanding-results)
- [Demo API and intentional vulnerabilities](#demo-api-and-intentional-vulnerabilities)
- [API reference](#api-reference)
- [Architecture](#architecture)
- [Security model](#security-model)
- [Verification and test evidence](#verification-and-test-evidence)
- [Limitations and roadmap](#limitations-and-roadmap)
- [Contributing](#contributing)
- [License](#license)

## Why this exists

Authorization bugs are logic bugs. Status codes alone do not prove security: a `200 OK` may still leak another user's data, and a `403` on one endpoint means little if a sibling endpoint or HTTP method enforces a different rule.

This tool tests the **policy you configure** — not hardcoded assumptions about roles or JWTs — and reports only contradictions between expected and observed behavior, with reproducible evidence for each claim.

## Key capabilities

| Area | What is implemented |
|---|---|
| Policy-driven testing | Validated JSON policy: path, method, `requires_auth`, `allowed_roles`, `ownership_required`, `sensitivity`, safe payloads, params/headers, per-endpoint resource overrides |
| Identity matrix | Roles are examples (`admin`, `user`, `readonly`, `none`), never assumed. Auth states: `valid`, `missing`, `invalid`, `expired` |
| Object-level checks | Own vs. other resource substitution with response-body leak inspection — not status-code-only verdicts |
| Consistency analysis | Flags PUT vs. PATCH, secure vs. sibling-endpoint, and auth vs. no-auth divergences only when the policy demands the same outcome |
| Transparent classification | Rule-based severity (`Critical / High / Medium / Low / Informational`) plus `confirmed / suspicious / inconclusive` confidence. Failed tests are not all Critical |
| Reporting | JSON, findings CSV, results CSV, and concise HTML. Tokens and secrets redacted in every artifact |
| Regression | Re-run the same suite and diff by finding fingerprint: `new / resolved / unchanged` |
| Safety | Localhost/lab allowlist, DNS + IP revalidation, redirect re-checks, timeouts, bounded concurrency, destructive-method opt-in, TLS verification on |

## Repository layout

```text
backend/
  app/
    main.py                 # FastAPI: health, policy validation, scans, reports, diff
    schemas/policy.py       # Pydantic models for policy, identities, results, findings
    services/engine/        # Reusable engine (no frontend required)
      testcase_gen.py       # Endpoint x identity x auth-state x resource expansion
      executor.py           # httpx execution with SSRF and redirect guards
      ownership.py          # Body-leak detection and verdict state machine
      analyzers.py          # Failure-to-finding mapping and consistency analysis
      severity.py           # Deterministic severity and remediation table
      scanner.py            # Bounded orchestration with live progress
      reporter.py           # JSON / CSV / HTML builders (redacted)
    security/
      target_validator.py   # Allowlist, DNS/IP, rebinding and redirect guards
      redaction.py          # Header, body, and dict redaction helpers
    store/file_store.py     # Memory + reports/scans/*.json (no database)
  tests/test_engine.py      # Unit + integration tests
demo_api/
  app/main.py               # Isolated lab API: synthetic users, orders, JWT
  VULNS.md                  # Documents V1–V3 and their secure twins
frontend/
  src/
    pages/                  # Dashboard, NewScan, Results, Settings
    components/Layout.tsx   # Sidebar + top bar shell, status color system
    services/api.ts         # Typed fetch client (real backend only)
    types.ts                # Shared scan, result, and finding types
examples/sample_policy.json # Copy-paste starter policy with resource overrides
reports/
  example-scan.json         # Real scan output against the local demo API
  example-findings.csv
  example-results.csv
  example-report.html
scripts/
  e2e_scan.py               # End-to-end driver: tokens, scan, poll, exports, diff
  inspect_scan.py           # Local result triage helper
  check_redaction.py        # Fails if a real JWT appears in reports
docs/ARCHITECTURE.md        # Component and data-flow reference
```

## Quickstart

Prerequisites: **Python 3.11+**, **Node 18+ / npm**, PowerShell or any POSIX shell. No Docker or cloud account needed.

```powershell
# 1 — Python environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1            # macOS/Linux: source .venv/bin/activate
pip install -r backend/requirements.txt -r demo_api/requirements.txt
Copy-Item .env.example .env             # macOS/Linux: cp .env.example .env

# 2 — Demo lab API (terminal 1)
python -m uvicorn demo_api.app.main:app --host 127.0.0.1 --port 8001

# 3 — Testing backend (terminal 2)
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000

# 4 — Frontend (terminal 3)
cd frontend
npm install
npm run dev                             # http://localhost:5173 (proxies /api to :8000)

# 5 — Automated tests
python -m pytest backend/tests/test_engine.py -q

# 6 — Full end-to-end scan (both APIs running, from repo root)
python scripts/e2e_scan.py
```

Health checks:

- Backend: `GET http://127.0.0.1:8000/api/health` → `{"status":"ok"}`
- Demo tokens: `GET http://127.0.0.1:8001/demo/tokens`

Production frontend check: `cd frontend && npm run build`.

## Configuring a scan

### Option A — Web UI (recommended for first run)

1. Open `http://localhost:5173/scans/new`.
2. Set target to `http://127.0.0.1:8001`.
3. Paste `examples/sample_policy.json` into the policy editor.
4. Click **Fetch demo tokens** to inject short-lived local JWTs (never commit real tokens).
5. Tick **Allow PUT/PATCH/POST/DELETE tests** only if you intend state-changing checks against your isolated lab.
6. Confirm you are authorized to test the target, then **Launch scan**. Progress is polled from the backend — there is no simulated progress bar.

### Option B — JSON policy file

```jsonc
{
  "target_base_url": "http://127.0.0.1:8001",
  "endpoints": [
    {
      "id": "get-user",
      "path": "/api/users/{id}",
      "method": "GET",
      "requires_auth": true,
      "allowed_roles": ["admin", "user", "readonly"],
      "ownership_required": true,
      "sensitivity": "private"
    }
  ],
  "identities": [
    {
      "name": "alice",
      "role": "user",
      "auth_state": "valid",
      "token": "<local-demo-jwt>",
      "own_resource_id": "u_alice",
      "other_resource_id": "u_bob",
      "resources": {
        "get-order": { "own": "o_alice1", "other": "o_bob1" },
        "vuln-order": { "own": "o_alice1", "other": "o_bob1" }
      }
    },
    { "name": "anonymous", "role": "none", "auth_state": "missing" }
  ]
}
```

Notes:

- `{id}`, `{user_id}`, `{order_id}`, and `{resource_id}` are substituted per test variant (`own` / `other`).
- `resources` overrides the generic IDs for endpoints whose fixtures differ (for example orders vs. users).
- `safe_payload` is sent only for `POST` / `PUT` / `PATCH` when destructive tests are explicitly enabled.
- Validate any policy first: `POST /api/policy/validate`.

## Understanding results

Each test records method, rendered path, identity, role, auth state, resource variant, expected outcome, actual status, verdict, leak flag, redacted body excerpt, timing, and error.

Verdict rules:

- `pass` — observed behavior matches policy (including `401`/`403`, and `404` when a denied resource is hidden).
- `fail` — observed behavior contradicts policy, optionally with confirmed body disclosure.
- `inconclusive` — timeout, connection failure, `5xx`, blocked redirect, or missing fixture (`404` where access was expected). Inconclusive tests are never marked passed.

Findings include a stable ID, endpoint + method, category, severity, expected vs. actual behavior, explanation, step-by-step reproduction, redacted evidence, remediation, confidence, and a fingerprint used for regression diffs.

Severity is intentionally conservative:

- `Critical` — unauthenticated access to admin or write paths; confirmed cross-user writes.
- `High` — confirmed cross-user reads (BOLA/IDOR); missing auth on sensitive reads.
- `Medium` — accepted invalid/expired tokens; PUT vs. PATCH divergence; role over-grant on reads.
- `Low / Informational` — minor inconsistencies and hardening notes.

The dashboard surfaces the latest scan first. The results page supports severity, category, and text filtering, expandable finding details, capped result tables with full CSV/JSON exports, and a previous-scan comparison box.

## Demo API and intentional vulnerabilities

The demo API uses synthetic users (`admin`, `alice`, `bob`, `readonly`) and orders (`o_alice1`, `o_bob1`) with short-lived local JWTs. Full details: [`demo_api/VULNS.md`](demo_api/VULNS.md).

| ID | Endpoint | Intended flaw | Secure counterpart |
|---|---|---|---|
| V1 | `GET /vuln/orders/{id}` | BOLA — any authenticated user can read any order | `GET /api/orders/{id}` enforces owner-or-admin |
| V2 | `GET /vuln/admin-export` | Missing authentication — full dump with no credentials | `GET /api/admin/stats` requires an admin JWT |
| V3 | `PATCH /api/users/{id}` | Inconsistent ownership — `PUT` checks owner, `PATCH` does not | `PUT /api/users/{id}` enforces owner-or-admin |

> Local lab only. Do not deploy `demo_api` publicly or reuse its signing secret outside this repository.

## API reference

| Method and path | Purpose |
|---|---|
| `GET /api/health` | Backend liveness |
| `POST /api/policy/validate` | Validate endpoint and identity configuration |
| `POST /api/scans` | Launch a scan (requires `confirm_target: true`; rejects unapproved hosts and non-opted-in destructive methods) |
| `GET /api/scans` | List scans with summaries |
| `GET /api/scans/{id}` | Scan detail with live progress, results, and findings |
| `GET /api/scans/{id}/findings?severity=&category=&q=` | Filtered findings |
| `GET /api/scans/{id}/report.json` | Full machine-readable report |
| `GET /api/scans/{id}/report.csv?kind=findings\|results` | CSV exports |
| `GET /api/scans/{id}/report.html` | Concise human-readable report |
| `GET /api/scans/{id}/diff?against={previous}` | Regression comparison (`new / resolved / unchanged`) |
| `GET /api/demo/info` | Demo target hint |

## Architecture

```text
Browser (Vite + React)
  └─▶ Backend FastAPI :8000 ──▶ Demo / Lab API :8001
        │ engine pipeline
        ├─ testcase_gen → executor → ownership/verdict → analyzers → reporter
        └─ store: reports/scans/*.json
```

Flow: `ScanRequest → expand_cases → bounded httpx execution (SSRF-checked) → verdict + leak check → findings + consistency pass → summary → persisted ScanRecord → JSON/CSV/HTML`.

Deliberate choices:

- File-based store instead of SQLite — single-operator lab tool with no concurrency requirements.
- `httpx` async client — explicit timeout, redirect, and connection control.
- Deterministic rules instead of ML — every severity and category is traceable to `severity.py` and `analyzers.py`.
- Fixture-aware verdicts — a missing test object yields `inconclusive`, not a vulnerability.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for module responsibilities.

## Security model

- Scanning limited to `localhost` / `127.0.0.1` / `::1` plus explicit `ALLOWED_TARGETS`. Anything else is rejected with a safe alternative.
- DNS is resolved and IP-checked before requests; redirects are revalidated and blocked off-base. Link-local (`169.254.x.x`), multicast, reserved, and — by default — private ranges are refused unless `ALLOW_PRIVATE_TARGETS=true` in an isolated lab.
- No credentials in target URLs. No arbitrary redirects followed. TLS verification stays enabled.
- Timeouts (default 10s), concurrency cap (default 5), and a small rate delay bound scan pressure.
- State-changing methods are skipped unless `include_destructive: true` is explicitly set for an authorized target.
- `Authorization` headers, passwords, tokens, cookies, and JWT-shaped strings are redacted from evidence, logs, and exports. `scripts/check_redaction.py` enforces this in verification.
- The engine never executes user-supplied code or shell commands.

## Verification and test evidence

```powershell
python -m pytest backend/tests/test_engine.py -q   # 13 passed
cd frontend; npm run build                          # production build succeeds
python scripts/e2e_scan.py                         # live scan + exports + diff
python scripts/check_redaction.py                   # no real JWT in reports
```

Reference end-to-end result against the current demo policy (98 tests):

- `86 passed · 12 failed · 0 inconclusive`
- Findings: `BOLA 5 · BrokenAccessControl 6 · Consistency 2 · RoleEnforcement 1`
- Severity: `Critical 8 · High 3 · Medium 3`
- Secure endpoints (`/api/users/me`, `/api/users/{id}`, `PUT /api/users/{id}`, `/api/admin/stats`, `/api/public/info`, `/api/orders/{id}`) produce no findings
- Curated artifacts: `reports/example-scan.json`, `reports/example-findings.csv`, `reports/example-results.csv`, `reports/example-report.html`

## Limitations and roadmap

**Current scope is intentional:**

- Bearer-token authentication is implemented and tested first; other schemes are not claimed.
- Roles are policy-defined examples, not a fixed hierarchy.
- Single-worker scans with file persistence; no hosted multi-tenant mode.
- No load testing, crawling, or generic vulnerability scanning beyond authorization consistency.

**Sensible next steps:**

- OpenAPI import to bootstrap endpoint policies.
- Per-endpoint rate limits and retry budgets.
- Token-tampering cases (role claim, `alg=none`, cross-secret JWTs) against lab targets.
- Scheduled regression with stored baselines.

## Contributing

1. Keep the engine deterministic and UI-free of hardcoded results.
2. Add a unit test for every new verdict, severity, or validation rule.
3. Verify against the demo API and include before/after scan summaries in the PR.
4. Never commit credentials, tokens, or generated scan history beyond `reports/example-*`.

## License

MIT — see [`LICENSE`](LICENSE). The intentionally vulnerable demo API is provided strictly for local authorized testing.
