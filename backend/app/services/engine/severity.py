"""Transparent rule-based severity + category mapping."""
from __future__ import annotations


def classify(category: str, sensitivity: str, method: str, auth_state: str, leak: bool) -> tuple[str, str, str]:
    """Returns (severity, confidence, remediation). Documented, deterministic."""
    write = method in ("POST", "PUT", "PATCH", "DELETE")
    unauth = auth_state in ("missing", "invalid", "expired") or auth_state == "none"

    if category in ("BOLA", "IDOR"):
        if write:
            return ("Critical", "confirmed" if leak else "suspicious",
                    "Enforce server-side ownership checks on every object access (not just list views); "
                    "use indirect references or verify owner_id == caller on write paths.")
        return ("High", "confirmed" if leak else "suspicious",
                "Enforce ownership check: compare requested object owner against authenticated caller; "
                "return 403/404 without disclosing data.")
    if category == "BrokenAccessControl" and sensitivity == "admin":
        return ("Critical", "confirmed",
                "Require admin role server-side on this endpoint; deny by default; audit role middleware ordering.")
    if unauth and sensitivity in ("admin", "private", "write"):
        if not write and sensitivity == "private":
            return ("High", "confirmed", "Require authentication on this endpoint; return 401 when credentials are absent/invalid.")
        return ("Critical", "confirmed", "Require authentication before authorization; return 401 for missing/invalid/expired credentials.")
    if category == "RoleEnforcement":
        if write:
            return ("High", "confirmed", "Check role server-side per method; readonly roles must receive 403 on state-changing methods.")
        return ("Medium", "confirmed", "Enforce allowed_roles per endpoint; deny by default and test each role explicitly.")
    if category == "Authentication":
        return ("Medium", "confirmed" if not leak else "suspicious",
                "Validate token signature and expiry on every request; distinguish 401 (authN) from 403 (authZ).")
    if category == "Consistency":
        return ("Medium", "suspicious",
                "Align authorization across related endpoints/methods (GET vs GET, PUT vs PATCH); "
                "share one authorization helper instead of per-handler checks.")
    return ("Low", "suspicious", "Review handler authorization logic and add explicit deny-by-default tests.")
