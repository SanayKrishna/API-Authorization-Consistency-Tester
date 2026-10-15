# Intentionally vulnerable endpoints — LOCAL LAB ONLY.
# Never expose demo_api publicly. These vulns exist so the tester has known-positives.

| ID | Endpoint | Flaw | Secure twin |
|----|----------|------|-------------|
| V1 | `GET /vuln/orders/{id}` | BOLA: authenticated user can read any order (no owner check) | `GET /api/orders/{id}` enforces owner-or-admin |
| V2 | `GET /vuln/admin-export` | Missing authentication: full user/order dump with no credentials | `GET /api/admin/stats` requires admin JWT |
| V3 | `PATCH /api/users/{id}` | Inconsistent ownership: PUT checks owner, PATCH does not | `PUT /api/users/{id}` enforces owner-or-admin |

Expected scanner behavior:
- alice reading `o_bob1` via `/vuln/orders/{id}` → FAIL (BOLA, High, confirmed leak)
- unauthenticated `GET /vuln/admin-export` → FAIL (BrokenAccessControl, Critical)
- alice PATCHing `u_bob` → FAIL while PUT is denied → FAIL + Consistency finding
- alice reading own profile, admin reading stats → PASS (no findings)
